import boto3
import json
from result_output import ResultOutput
import importlib.util
import sys
from decimal import Decimal
from boto3.dynamodb.conditions import Key, Attr
from pprint import pprint
import urllib3
import requests

class Activity:
    test_passed = "Test Passed"
    test_failed = "Test Failed"

    # === RESOURCE NAMES (customize based on assessment) ===
    LAMBDA_POST_ROLE = "lambda-post-role"
    STEP_FUNCTION_INVOKE_LAMBDA_ROLE = "step-function-invoke-lambda"
    PROCESS_PAYMENT_LAMBDA = "process-payment"
    PROCESS_RESTAURANT_LAMBDA = "process-restaurant"
    UPDATE_ORDER_FROM_PENDING_STATE_LAMBDA = "update-order-from-pending-state"
    PROCESS_ORDER_STATUS_STEP_FUNCTION = "process-order-status"
    ORDER_STATUS_NOTIFIER_TOPIC = "order-status-notifier"
    ORDERS_ASYNC_DEAD_LETTER_QUEUE = "orders-async-dead-letter-queue"
    ORDERS_ASYNC_QUEUE = "orders-async-queue"
    ORDERS_API_GATEWAY = "orders-api"
    ORDERS_DATABASE_TABLE = "orders-database"

    # === HELPER METHODS ===

    @staticmethod
    def compare_two_dictionaries(dictionary_1, dictionary_2):
        return sorted(dictionary_1, key=lambda item: sorted(item.items())) == \
               sorted(dictionary_2, key=lambda item: sorted(item.items()))

    def return_url_if_queue_created(self, session, queue_name):
        client = session.client('sqs')
        for queue_url in client.list_queues().get('QueueUrls', []):
            if queue_url.split("/")[-1] == queue_name:
                return True, queue_url
        return False, ''

    def if_api_gateway_is_created_return_id_and_endpoint(self, session, api_name):
        client = session.client('apigatewayv2')
        for api in client.get_apis()['Items']:
            if api['Name'] == api_name and api['ProtocolType'] == "HTTP":
                return True, api['ApiId'], api['ApiEndpoint']
        return False, '', ''

    def check_if_all_policies_are_attached_to_role(self, session, role_name, policies):
        policy_status = {policy: False for policy in policies}
        iam_client = session.client('iam')
        for role in iam_client.list_roles()['Roles']:
            if role['RoleName'] == role_name:
                for policy in iam_client.list_attached_role_policies(RoleName=role['RoleName'])['AttachedPolicies']:
                    if policy['PolicyName'] in policy_status:
                        policy_status[policy['PolicyName']] = True
        return all(policy_status.values())

    def if_topic_is_created_return_arn(self, session, topic_name):
        sns_client = session.client('sns')
        for topic in sns_client.list_topics()['Topics']:
            if topic['TopicArn'].split(":")[-1] == topic_name:
                return True, topic['TopicArn']
        return False, ''

    def return_arn_if_step_function_is_created(self, session, state_machine_name):
        step_function_client = session.client('stepfunctions')
        for sf in step_function_client.list_state_machines()['stateMachines']:
            if sf['name'] == state_machine_name:
                return True, sf['stateMachineArn']
        return False, ''

    def check_if_lambda_function_exists(self, session, function_name, expected_runtime=None):
        lambda_client = session.client('lambda')
        for function in lambda_client.list_functions()['Functions']:
            if function['FunctionName'] == function_name:
                if expected_runtime is None or expected_runtime in function['Runtime']:
                    return True, function
        return False, None

    def check_if_s3_bucket_exists(self, session, bucket_name_prefix=None, bucket_name_exact=None):
        s3_client = session.client('s3')
        for bucket in s3_client.list_buckets()['Buckets']:
            if bucket_name_exact and bucket['Name'] == bucket_name_exact:
                return True, bucket['Name']
            if bucket_name_prefix and bucket['Name'].startswith(bucket_name_prefix):
                return True, bucket['Name']
        return False, None

    def check_if_dynamodb_table_exists(self, session, table_name):
        dynamodb_client = session.client('dynamodb')
        try:
            response = dynamodb_client.describe_table(TableName=table_name)
            return True, response['Table']
        except dynamodb_client.exceptions.ResourceNotFoundException:
            return False, None

    # === VALIDATION METHODS ===

    def testcase_check_lambda_post_role_policies(self, session, test_object):
        testcase_description = f"Checking for policies attached to role {self.LAMBDA_POST_ROLE}"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        expected = f"Role {self.LAMBDA_POST_ROLE} created with required policies attached"
        actual = f"Role NOT created or policies NOT attached"
        test_object.update_pre_result(testcase_description, expected)
        try:
            policies = {"AWSStepFunctionsFullAccess"}
            if self.check_if_all_policies_are_attached_to_role(session, self.LAMBDA_POST_ROLE, policies):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_step_function_invoke_lambda_role(self, session, test_object):
        testcase_description = f"Checking for policies attached to role {self.STEP_FUNCTION_INVOKE_LAMBDA_ROLE}"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        expected = f"Role {self.STEP_FUNCTION_INVOKE_LAMBDA_ROLE} created with required policies attached"
        actual = f"Role NOT created or policies NOT attached"
        test_object.update_pre_result(testcase_description, expected)
        try:
            policies = {"AWSLambdaRole", "AmazonSNSFullAccess"}
            if self.check_if_all_policies_are_attached_to_role(session, self.STEP_FUNCTION_INVOKE_LAMBDA_ROLE, policies):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_process_payment_lambda_function(self, session, test_object):
        testcase_description = f"Check for Lambda function {self.PROCESS_PAYMENT_LAMBDA}"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = f"Lambda function {self.PROCESS_PAYMENT_LAMBDA} created with correct runtime"
        actual = f"Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            lambda_client = session.client('lambda')
            for function in lambda_client.list_functions()['Functions']:
                if function['FunctionName'] == self.PROCESS_PAYMENT_LAMBDA and 'python' in function['Runtime']:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_process_restaurant_lambda_function(self, session, test_object):
        testcase_description = f"Check for Lambda function {self.PROCESS_RESTAURANT_LAMBDA}"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = f"Lambda function {self.PROCESS_RESTAURANT_LAMBDA} created with correct runtime"
        actual = f"Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            lambda_client = session.client('lambda')
            for function in lambda_client.list_functions()['Functions']:
                if function['FunctionName'] == self.PROCESS_RESTAURANT_LAMBDA and 'python' in function['Runtime']:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_update_order_status_lambda_function(self, session, test_object):
        testcase_description = f"Check for Lambda function {self.UPDATE_ORDER_FROM_PENDING_STATE_LAMBDA}"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = f"Lambda function {self.UPDATE_ORDER_FROM_PENDING_STATE_LAMBDA} created with correct runtime"
        actual = f"Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            lambda_client = session.client('lambda')
            for function in lambda_client.list_functions()['Functions']:
                if function['FunctionName'] == self.UPDATE_ORDER_FROM_PENDING_STATE_LAMBDA and 'python' in function['Runtime']:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_step_function_creation(self, session, test_object):
        testcase_description = f"Check for Step Function {self.PROCESS_ORDER_STATUS_STEP_FUNCTION}"
        reference = "https://docs.aws.amazon.com/step-functions/latest/dg/"
        expected = "Step function created with correct state configuration"
        actual = "Step function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            step_function_client = session.client('stepfunctions')
            for sf in step_function_client.list_state_machines()['stateMachines']:
                if sf['name'] == self.PROCESS_ORDER_STATUS_STEP_FUNCTION:
                    description = step_function_client.describe_state_machine(stateMachineArn=sf['stateMachineArn'])
                    if description['status'] == 'ACTIVE':
                        actual = expected
                        return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_step_function_states_configuration(self, session, test_object):
        testcase_description = f"Check Step Function {self.PROCESS_ORDER_STATUS_STEP_FUNCTION} for required states"
        reference = "https://docs.aws.amazon.com/step-functions/latest/dg/"
        expected = "Step function has all required states: ProcessPayment, WaitForPayment, PaymentStatus, ProcessRestaurant, UpdateOrderStatus, PaymentFailed, SendOrderStatus"
        actual = "Step function does NOT have all required states"
        test_object.update_pre_result(testcase_description, expected)
        try:
            step_function_client = session.client('stepfunctions')
            required_states = {"ProcessPayment", "WaitForPayment", "PaymentStatus", "ProcessRestaurant", "UpdateOrderStatus", "PaymentFailed", "SendOrderStatus"}
            for sf in step_function_client.list_state_machines()['stateMachines']:
                if sf['name'] == self.PROCESS_ORDER_STATUS_STEP_FUNCTION:
                    description = step_function_client.describe_state_machine(stateMachineArn=sf['stateMachineArn'])
                    definition = json.loads(description['definition'])
                    state_names = set(definition.get('States', {}).keys())
                    if required_states.issubset(state_names):
                        actual = expected
                        return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sns_topic_creation(self, session, test_object):
        testcase_description = f"Check for SNS Topic {self.ORDER_STATUS_NOTIFIER_TOPIC}"
        reference = "https://docs.aws.amazon.com/sns/latest/dg/"
        expected = f"SNS Topic {self.ORDER_STATUS_NOTIFIER_TOPIC} created"
        actual = f"SNS Topic NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            sns_client = session.client('sns')
            for topic in sns_client.list_topics()['Topics']:
                if topic['TopicArn'].split(":")[-1] == self.ORDER_STATUS_NOTIFIER_TOPIC:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sns_topic_email_subscription(self, session, test_object):
        testcase_description = f"Check for confirmed email subscription on SNS Topic {self.ORDER_STATUS_NOTIFIER_TOPIC}"
        reference = "https://docs.aws.amazon.com/sns/latest/dg/"
        expected = f"Confirmed email subscription exists for SNS Topic {self.ORDER_STATUS_NOTIFIER_TOPIC}"
        actual = f"Confirmed email subscription NOT found for SNS Topic"
        test_object.update_pre_result(testcase_description, expected)
        try:
            sns_client = session.client('sns')
            topic_arn = None
            for topic in sns_client.list_topics()['Topics']:
                if topic['TopicArn'].split(":")[-1] == self.ORDER_STATUS_NOTIFIER_TOPIC:
                    topic_arn = topic['TopicArn']
                    break
            if not topic_arn:
                return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            subs = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)['Subscriptions']
            for sub in subs:
                if sub['Protocol'] == 'email' and sub['SubscriptionArn'] != 'PendingConfirmation':
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sqs_dead_letter_queue(self, session, test_object):
        testcase_description = f"Check for SQS Queue {self.ORDERS_ASYNC_DEAD_LETTER_QUEUE}"
        reference = "https://docs.aws.amazon.com/AWSSimpleQueueService/"
        expected = f"SQS Queue {self.ORDERS_ASYNC_DEAD_LETTER_QUEUE} created"
        actual = f"SQS Queue NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            client = session.client('sqs')
            for queue_url in client.list_queues().get('QueueUrls', []):
                if queue_url.split("/")[-1] == self.ORDERS_ASYNC_DEAD_LETTER_QUEUE:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sqs_orders_queue(self, session, test_object):
        testcase_description = f"Check for SQS Queue {self.ORDERS_ASYNC_QUEUE} with dead letter queue configured"
        reference = "https://docs.aws.amazon.com/AWSSimpleQueueService/"
        expected = f"SQS Queue {self.ORDERS_ASYNC_QUEUE} created with dead letter queue configured"
        actual = f"SQS Queue NOT created or dead letter queue NOT configured"
        test_object.update_pre_result(testcase_description, expected)
        try:
            client = session.client('sqs')
            queue_url = None
            for url in client.list_queues().get('QueueUrls', []):
                if url.split("/")[-1] == self.ORDERS_ASYNC_QUEUE:
                    queue_url = url
                    break
            if not queue_url:
                return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            attrs = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['RedrivePolicy'])
            redrive_policy = attrs.get('Attributes', {}).get('RedrivePolicy')
            if redrive_policy:
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_api_gateway_creation(self, session, test_object):
        testcase_description = f"Check for API Gateway {self.ORDERS_API_GATEWAY}"
        reference = "https://docs.aws.amazon.com/apigateway/"
        expected = f"API Gateway {self.ORDERS_API_GATEWAY} created with HTTP protocol"
        actual = f"API Gateway NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            client = session.client('apigatewayv2')
            for api in client.get_apis()['Items']:
                if api['Name'] == self.ORDERS_API_GATEWAY and api['ProtocolType'] == "HTTP":
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_dynamodb_orders_table(self, session, test_object):
        testcase_description = f"Check for DynamoDB Table {self.ORDERS_DATABASE_TABLE}"
        reference = "https://docs.aws.amazon.com/dynamodb/"
        expected = f"DynamoDB table {self.ORDERS_DATABASE_TABLE} exists with correct schema"
        actual = f"DynamoDB table NOT created or schema incorrect"
        test_object.update_pre_result(testcase_description, expected)
        try:
            dynamodb_client = session.client('dynamodb')
            try:
                response = dynamodb_client.describe_table(TableName=self.ORDERS_DATABASE_TABLE)
                table = response['Table']
                # Example schema validation: PK = orderId, SK = status
                key_schema = table.get('KeySchema', [])
                key_names = {k['AttributeName'] for k in key_schema}
                if 'orderId' in key_names:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
                else:
                    return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            except dynamodb_client.exceptions.ResourceNotFoundException:
                return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

def start_tests(session, args):
    if "result_output" not in sys.modules:
        importlib.import_module("result_output")
    else:
        importlib.reload(sys.modules["result_output"])

    test_object = ResultOutput(args, Activity)
    challenge_test = Activity()

    # === CALL ALL VALIDATION METHODS ===
    challenge_test.testcase_check_lambda_post_role_policies(session, test_object)
    challenge_test.testcase_check_step_function_invoke_lambda_role(session, test_object)
    challenge_test.testcase_check_process_payment_lambda_function(session, test_object)
    challenge_test.testcase_check_process_restaurant_lambda_function(session, test_object)
    challenge_test.testcase_check_update_order_status_lambda_function(session, test_object)
    challenge_test.testcase_check_step_function_creation(session, test_object)
    challenge_test.testcase_check_step_function_states_configuration(session, test_object)
    challenge_test.testcase_check_sns_topic_creation(session, test_object)
    challenge_test.testcase_check_sns_topic_email_subscription(session, test_object)
    challenge_test.testcase_check_sqs_dead_letter_queue(session, test_object)
    challenge_test.testcase_check_sqs_orders_queue(session, test_object)
    challenge_test.testcase_check_api_gateway_creation(session, test_object)
    challenge_test.testcase_check_dynamodb_orders_table(session, test_object)

    json.dumps(test_object.result_final(), indent=4)
    return test_object.result_final()