#!/usr/bin/env python3
import json
import os
from datetime import datetime

class ResultOutput:
    def __init__(self, args, activity_class):
        self.results = []
        self.eval_message = {}
        self.total_marks = 0
        self.obtained_marks = 0
        try:
            args_dict = json.loads(args)
            self.token = args_dict.get('token', 'default')
        except:
            self.token = 'default'

    def update_pre_result(self, description, expected):
        '''Called before test execution'''
        pass

    def update_result(self, status, expected, actual, description, reference, marks=10, marks_obtained=0):
        '''
        Update test result
        status: 1 for pass, 0 for fail
        '''
        result = {
            "status": status,
            "description": description,
            "expected": expected,
            "actual": actual,
            "reference": reference,
            "marks": marks,
            "marks_obtained": marks_obtained,
            "statusText": "PASS" if status == 1 else "FAIL"
        }
        self.results.append(result)
        self.total_marks += marks
        self.obtained_marks += marks_obtained

        status_text = "PASS" if status == 1 else "FAIL"
        print(f"[{status_text}] {description} - Marks: {marks_obtained}/{marks}")
        return result

    def result_final(self):
        '''Generate final JSON result'''
        final_result = {
            "token": self.token,
            "timestamp": datetime.now().isoformat(),
            "total_marks": self.total_marks,
            "obtained_marks": self.obtained_marks,
            "percentage": round((self.obtained_marks / self.total_marks * 100), 2) if self.total_marks > 0 else 0,
            "testcases": self.results,
            "errors": self.eval_message
        }
        return json.dumps(final_result)

    def write_to_file(self, filepath="/tmp/clv/concept-eval.json"):
        '''Write results to file'''
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                f.write(self.result_final())
            print(f"Results written to: {filepath}")
        except Exception as e:
            print(f"Error writing results: {e}")
