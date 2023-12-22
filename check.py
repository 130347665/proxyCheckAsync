import aiohttp
import asyncio
import random
import re
from tqdm.asyncio import tqdm
import time
import platform
if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
class ProxyChecker:
    def __init__(self):
        self._ip = None
        self.proxy_judges = [
            'http://mojeip.net.pl/asdfa/azenv.php'
        ]

    async def get_ip(self):
        if self._ip is None:
            r = await self.send_query(url='https://api.ipify.org/')
            self._ip = r['response'] if r else ""
        return self._ip

    async def send_query(self, proxy=None, url=None, user=None, password=None):
        async with aiohttp.ClientSession() as session:
            start_time = time.time()  # Start timing before the request
            try:
                async with session.get(url or random.choice(self.proxy_judges), proxy=proxy, timeout=5) as response:
                    if response.status != 200:
                        return False
                    text = await response.text()
                    end_time = time.time()  # End timing after the request
                    timeout = round((end_time - start_time) * 1000)  # Calculate elapsed time in milliseconds
                    # print(f"Proxy: {proxy} | Timeout: {timeout}ms")
                    return {
                        'timeout': timeout,
                        'response': text
                    }
            except Exception as e:
                return False

    async def parse_anonymity(self, response):
        ip = await self.get_ip()
        if ip in response:
            return 'Transparent'

        privacy_headers = [
            'VIA', 'X-FORWARDED-FOR', 'X-FORWARDED', 'FORWARDED-FOR', 'FORWARDED-FOR-IP',
            'FORWARDED', 'CLIENT-IP', 'PROXY-CONNECTION'
        ]

        if any(header in response for header in privacy_headers):
            return 'Anonymous'

        return 'Elite'

    async def get_country(self, ip):
        r = await self.send_query(url='https://ip2c.org/' + ip)
        if r and r['response'][0] == '1':
            data = r['response'].split(';')
            return [data[3], data[1]]
        return ['-', '-']

    async def check_proxy(self, proxy, check_country=True, check_address=False, user=None, password=None):
        protocols = {}
        total_timeout = 0

        for protocol in ['http', 'socks4', 'socks5']:
            r = await self.send_query(proxy=f"{protocol}://{proxy}", user=user, password=password)
            if not r:
                continue
            protocols[protocol] = r
            total_timeout += r['timeout']

        if not protocols:
            return False

        response = random.choice(list(protocols.values()))['response']
        anonymity = await self.parse_anonymity(response)
        avg_timeout = total_timeout // len(protocols)

        results = {
            'ip': proxy,
            'protocols': list(protocols.keys()),
            'anonymity': anonymity,
            'timeout': avg_timeout
        }

        if check_country:
            country = await self.get_country(proxy.split(':')[0])
            results.update({
                'country': country[0],
                'country_code': country[1]
            })

        if check_address:
            remote_addr = re.search(r'REMOTE_ADDR = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', response)
            if remote_addr:
                results['remote_address'] = remote_addr.group(1)

        return results
    async def check_proxies_from_file(self, file_path, max_concurrent_tasks=10, check_country=True, check_address=False, user=None, password=None):
        # Read proxies from file
        with open(file_path, 'r') as file:
            proxies = file.read().splitlines()

        # Create a semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(max_concurrent_tasks)

        # Wrapper function to limit concurrency and pass additional parameters
        async def sem_task(proxy):
            async with semaphore:
                return await self.check_proxy(proxy, check_country, check_address, user, password)

        # Create tasks for each proxy
        tasks = [sem_task(proxy) for proxy in proxies]

        # Run the tasks and gather the results with a progress bar
        results = []
        for task in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Checking Proxies"):
            result = await task
            results.append(result)
        return results
    async def filter_proxies(self, proxies, anonymity:str=None, protocols:list=None, countries:list=None, timeout:int=None):
        filtered_proxies = []
        for proxy in proxies:
            if not proxy:
                continue
            if anonymity and proxy['anonymity'] != anonymity:
                continue
            if protocols and not set(protocols).issubset(set(proxy['protocols'])):
                continue
            if countries and proxy['country_code'] not in countries:
                continue
            if timeout and proxy['timeout'] > timeout:
                continue
            filtered_proxies.append(proxy)
        return filtered_proxies
    async def test_proxy(self, ip, protocol=None, user=None, password=None):
        protocols_to_test = ['http', 'socks4', 'socks5'] if protocol is None else [protocol]
        results = {}

        for protocol in protocols_to_test:
            proxy_url = f"{protocol}://{ip}"
            try:
                response = await self.send_query(proxy=proxy_url, url='https://www.google.com', user=user, password=password)
                if response and response['response']:
                    results[protocol] = {'status': 'success', 'timeout': response['timeout']}
                else:
                    results[protocol] = {'status': 'failed', 'timeout': None}
            except Exception as e:
                results[protocol] = {'status': 'failed', 'timeout': None, 'error': str(e)}

        return results

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