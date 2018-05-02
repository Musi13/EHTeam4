import shodan
import argparse
import sys
import itertools

SHODAN_API_KEY = "JgF8iUdjxdODTma08wfw2SySkJiGLBmK"
api = shodan.Shodan(SHODAN_API_KEY)
# default to search string for potential vulnerable hosts


def query_shodan(query='', limit=500):
    """
    @query: A string to be appended to the default search string. Syntax should follow Shodan specification.
    @limit: The maximum number of results to return.

    Query Shodan.io for hosts that match the given query 
    (and are also potentially vulnerable to ms08-067 or ms17-010).
    Returns a list of IP addresses as strings.
    """

    search_string = ' port:445 "SMB Version: 1" os:Windows !product:Samba ' + query

    print("Searching for string: \n"+search_string)

    try:
        results = api.search_cursor(search_string)  # an iterator for all pages of results

        return [r['ip_str'] for r in itertools.islice(results, limit)]

    except shodan.APIError as e:
        print('Error: %s' % e)
        sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search shodan for hosts vulnerable to EternalBlue')
    parser.add_argument('queries', nargs='*', help='additional search queries')
    parser.add_argument('--limit', help='maximum number of matching results to write to output, default being 500', default=500)
    parser.add_argument('--output', help='file to output the results to, default being shodan-search.out', default='shodan-search.out')
    parser.add_argument('--append', '-a', action='store_true', help='append to the output file')
    args = parser.parse_args()

    with open(args.output, 'a' if args.append else 'w') as f:
        f.write('\n'.join(query_shodan(' '.join(args.queries), int(args.limit))))
