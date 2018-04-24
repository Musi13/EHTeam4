import shodan
import argparse
import sys

SHODAN_API_KEY = "JgF8iUdjxdODTma08wfw2SySkJiGLBmK"
api = shodan.Shodan(SHODAN_API_KEY)
# defaulto search string for potential vulnerable hosts

def query_shodan(query='', limit=500, output='shodan-search.out', append=False):

    search_string = ' port:445 "SMB Version: 1" os:Windows !product:Samba ' + query

    output = output if output else 'shodan-search.out'
    limit = limit if limit else 500

    print("Searching for string: \n"+search_string)

    try:
        total = 0
        results = api.search_cursor(search_string)  # an iterator for all pages of results
        
        mode = 'w'
        if append:
            mode = 'a'
        
        with open(output, mode) as f:
            for i, result in enumerate(results):
                if i >= limit:
                    break
                f.write(result['ip_str']+"\n")
            total = i

        f.close()
        print("Number of results output to %s: %d\n" % (output, total))

    except shodan.APIError as e:
        print('Error: %s' % e)
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Search shodan for hosts vulnerable to EternalBlue')
    parser.add_argument('queries', nargs='*', help='additional search queries')
    parser.add_argument('--limit', help='maximum number of matching results to write to output, default being 500')
    parser.add_argument('--output', help='file to output the results to, default being shodan-search.out')
    parser.add_argument('--append', '-a', action='store_true', help='append to the output file')
    args = parser.parse_args()

    query_shodan(' '.join(args.queries), int(args.limit), args.output, args.append)