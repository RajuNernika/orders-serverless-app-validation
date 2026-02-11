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
    LAMBDA_POST_ROLE_NAME = "lambda-post-role"
    REQUIRED_POLICY = "AWSStepFunctionsFullAccess"

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
        expected = f"Role {self.LAMBDA_POST_ROLE_NAME} created with {self.REQUIRED_POLICY} policy attached"
        actual = f"Role {self.LAMBDA_POST_ROLE_NAME} NOT created or {self.REQUIRED_POLICY} policy NOT attached"
        test_object.update_pre_result(testcase_description, expected)
        try:
            policies = {self.REQUIRED_POLICY}
            if self.check_if_all_policies_are_attached_to_role(session, self.LAMBDA_POST_ROLE_NAME, policies):
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

    json.dumps(test_object.result_final(), indent=4)
    return test_object.result_final()