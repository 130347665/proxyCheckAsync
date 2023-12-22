# A simple Proxy check use Async

## Install
```
    pip install -r requirement.txt
```
## usege Example
```
# Example usage
async def main():
    checker = ProxyChecker()
    results = await checker.check_proxies_from_file('proxy.txt', 1000)
    # print(results)
    # filter_results = await checker.filter_proxies(results, protocols=['socks5,socks4'], timeout=1000)
    filter_results = await checker.filter_proxies(results, timeout=15000)
    with open('filter_result.txt', 'w') as file:
            for filter_result in filter_results:
                file.write(str(filter_result['ip']) + '\n')
if __name__ == '__main__':
    asyncio.run(main())
```
