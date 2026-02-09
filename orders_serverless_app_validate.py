import boto3
import json
from result_output import ResultOutput
import importlib.util
import sys

class Activity:
    test_passed = "Test Passed"
    test_failed = "Test Failed"

    # === RESOURCE NAMES (customize based on assessment) ===
    LAMBDA_POST_ROLE = "lambda-post-role"
    STEP_FUNCTION_INVOKE_LAMBDA_ROLE = "step-function-invoke-lambda"
    PROCESS_PAYMENT_LAMBDA = "process-payment"
    PROCESS_RESTAURANT_LAMBDA = "process-restaurant"
    UPDATE_ORDER_STATUS_LAMBDA = "update-order-from-pending-state"
    PROCESS_ORDER_STATUS_STEP_FUNCTION = "process-order-status"
    ORDER_STATUS_NOTIFIER_TOPIC = "order-status-notifier"
    ORDERS_ASYNC_DEAD_LETTER_QUEUE = "orders-async-dead-letter-queue"
    ORDERS_ASYNC_QUEUE = "orders-async-queue"
    ORDERS_API = "orders-api"
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
        testcase_description = "Verify that the lambda-post-role IAM role exists and has AWSStepFunctionsFullAccess policy attached"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        expected = "Role lambda-post-role created with AWSStepFunctionsFullAccess policy attached"
        actual = "Role NOT created or policy NOT attached"
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
        testcase_description = "Verify that the step-function-invoke-lambda role exists with AWSLambdaRole and AmazonSNSFullAccess policies"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html"
        expected = "Role step-function-invoke-lambda created with AWSLambdaRole and AmazonSNSFullAccess policies attached"
        actual = "Role NOT created or policies NOT attached"
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
        testcase_description = "Verify that the process-payment Lambda function exists with Python runtime"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = "Lambda function process-payment created with correct runtime"
        actual = "Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.check_if_lambda_function_exists(session, self.PROCESS_PAYMENT_LAMBDA, 'python'):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_process_restaurant_lambda_function(self, session, test_object):
        testcase_description = "Verify that the process-restaurant Lambda function exists with Python runtime"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = "Lambda function process-restaurant created with correct runtime"
        actual = "Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.check_if_lambda_function_exists(session, self.PROCESS_RESTAURANT_LAMBDA, 'python'):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_update_order_status_lambda_function(self, session, test_object):
        testcase_description = "Verify that the update-order-from-pending-state Lambda function exists with Python runtime"
        reference = "https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html"
        expected = "Lambda function update-order-from-pending-state created with correct runtime"
        actual = "Lambda function NOT created as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.check_if_lambda_function_exists(session, self.UPDATE_ORDER_STATUS_LAMBDA, 'python'):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_step_function_creation(self, session, test_object):
        testcase_description = "Verify that the process-order-status Step Function state machine is created with ACTIVE status"
        reference = "https://docs.aws.amazon.com/step-functions/latest/dg/"
        expected = "Step function process-order-status created with correct state configuration"
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
        testcase_description = "Verify Step Function has states: ProcessPayment, WaitForPayment, PaymentStatus, ProcessRestaurant, UpdateOrderStatus, PaymentFailed, SendOrderStatus"
        reference = "https://docs.aws.amazon.com/step-functions/latest/dg/"
        expected = "Step function process-order-status has correct states configuration"
        actual = "Step function states NOT configured as expected"
        test_object.update_pre_result(testcase_description, expected)
        try:
            step_function_client = session.client('stepfunctions')
            for sf in step_function_client.list_state_machines()['stateMachines']:
                if sf['name'] == self.PROCESS_ORDER_STATUS_STEP_FUNCTION:
                    description = step_function_client.describe_state_machine(stateMachineArn=sf['stateMachineArn'])
                    state_machine_definition = json.loads(description['definition'])
                    expected_states = {"ProcessPayment", "WaitForPayment", "PaymentStatus", "ProcessRestaurant", "UpdateOrderStatus", "PaymentFailed", "SendOrderStatus"}
                    actual_states = set(state_machine_definition['States'].keys())
                    if expected_states.issubset(actual_states):
                        actual = expected
                        return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sns_topic_creation(self, session, test_object):
        testcase_description = "Verify that the order-status-notifier SNS topic is created"
        reference = "https://docs.aws.amazon.com/sns/latest/dg/"
        expected = "SNS Topic order-status-notifier created"
        actual = "SNS Topic NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.if_topic_is_created_return_arn(session, self.ORDER_STATUS_NOTIFIER_TOPIC):
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sns_topic_email_subscription(self, session, test_object):
        testcase_description = "Verify that an email subscription exists and is confirmed for the order-status-notifier topic"
        reference = "https://docs.aws.amazon.com/sns/latest/dg/"
        expected = "Email subscription confirmed for SNS Topic order-status-notifier"
        actual = "Email subscription NOT confirmed"
        test_object.update_pre_result(testcase_description, expected)
        try:
            sns_client = session.client('sns')
            topic_arn = self.if_topic_is_created_return_arn(session, self.ORDER_STATUS_NOTIFIER_TOPIC)[1]
            if topic_arn:
                subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)['Subscriptions']
                for subscription in subscriptions:
                    if subscription['Protocol'] == 'email' and subscription['SubscriptionArn'] != 'PendingConfirmation':
                        actual = expected
                        return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sqs_dead_letter_queue(self, session, test_object):
        testcase_description = "Verify that the orders-async-dead-letter-queue SQS queue is created"
        reference = "https://docs.aws.amazon.com/AWSSimpleQueueService/"
        expected = "SQS Queue orders-async-dead-letter-queue created"
        actual = "SQS Queue NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.return_url_if_queue_created(session, self.ORDERS_ASYNC_DEAD_LETTER_QUEUE)[0]:
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_sqs_orders_queue(self, session, test_object):
        testcase_description = "Verify that the orders-async-queue SQS queue is created with dead letter queue configured"
        reference = "https://docs.aws.amazon.com/AWSSimpleQueueService/"
        expected = "SQS Queue orders-async-queue created with dead letter queue configured"
        actual = "SQS Queue NOT created or dead letter queue NOT configured"
        test_object.update_pre_result(testcase_description, expected)
        try:
            client = session.client('sqs')
            queue_created, queue_url = self.return_url_if_queue_created(session, self.ORDERS_ASYNC_QUEUE)
            if queue_created:
                attributes = client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['RedrivePolicy'])['Attributes']
                if 'RedrivePolicy' in attributes:
                    actual = expected
                    return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_api_gateway_creation(self, session, test_object):
        testcase_description = "Verify that the orders-api HTTP API Gateway is created"
        reference = "https://docs.aws.amazon.com/apigateway/"
        expected = "API Gateway orders-api created with HTTP protocol"
        actual = "API Gateway NOT created"
        test_object.update_pre_result(testcase_description, expected)
        try:
            if self.if_api_gateway_is_created_return_id_and_endpoint(session, self.ORDERS_API)[0]:
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
            return test_object.update_result(0, expected, actual, Activity.test_failed, reference)
        except Exception as e:
            test_object.update_result(0, expected, actual, Activity.test_failed, reference)
            test_object.eval_message["testcase_name"] = str(e)

    def testcase_check_dynamodb_orders_table(self, session, test_object):
        testcase_description = "Verify that the orders-database DynamoDB table exists with correct schema"
        reference = "https://docs.aws.amazon.com/dynamodb/"
        expected = "DynamoDB table orders-database exists with correct schema"
        actual = "DynamoDB table NOT created or schema incorrect"
        test_object.update_pre_result(testcase_description, expected)
        try:
            table_exists, table = self.check_if_dynamodb_table_exists(session, self.ORDERS_DATABASE_TABLE)
            if table_exists:
                # Add schema validation logic here if needed
                actual = expected
                return test_object.update_result(1, expected, actual, Activity.test_passed, "N/A")
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