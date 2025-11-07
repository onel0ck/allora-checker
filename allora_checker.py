#!/usr/bin/env python3

import requests
import time
from typing import Optional, List
from dataclasses import dataclass
import sys
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


logger.remove()
logger.add(
    sys.stdout,
    format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>",
    level="INFO"
)
logger.add("checker.log", rotation="10 MB", level="DEBUG")


@dataclass
class CheckResult:
    address: str
    boost_eligible: bool
    airdrop_eligible: bool
    boost_rate: float
    tier_name: str
    airdrop_allocation: Optional[float]
    error: Optional[str] = None


class AlloraChecker:
    def __init__(self):
        self.url = "https://prime.allora.foundation/api/upshot-api-proxy/allora/prime/"
        self.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'referer': 'https://prime.allora.foundation/connect-wallet',
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def check_address(self, address: str, proxy: Optional[str] = None, retry_count: int = 3) -> CheckResult:
        for attempt in range(retry_count):
            try:
                proxies = None
                if proxy:
                    proxies = {
                        'http': proxy,
                        'https': proxy
                    }
                
                response = requests.get(
                    f"{self.url}{address}",
                    headers=self.headers,
                    proxies=proxies,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('status') and 'data' in data:
                        result_data = data['data']
                        tier = result_data.get('default_tier') or {}
                        
                        return CheckResult(
                            address=address,
                            boost_eligible=result_data.get('boost_eligible', False),
                            airdrop_eligible=result_data.get('airdrop_eligible', False),
                            boost_rate=tier.get('boost_rate', 0),
                            tier_name=tier.get('name', 'NONE'),
                            airdrop_allocation=result_data.get('airdrop_allocation')
                        )
                    else:
                        return CheckResult(
                            address=address,
                            boost_eligible=False,
                            airdrop_eligible=False,
                            boost_rate=0,
                            tier_name='ERROR',
                            airdrop_allocation=None,
                            error=data.get('apiResponseMessage', 'Unknown error')
                        )
                else:
                    if attempt < retry_count - 1:
                        logger.debug(f"Retry {attempt + 1}/{retry_count} for {address[:10]}...")
                        time.sleep(2)
                        continue
                    return CheckResult(
                        address=address,
                        boost_eligible=False,
                        airdrop_eligible=False,
                        boost_rate=0,
                        tier_name='ERROR',
                        airdrop_allocation=None,
                        error=f"HTTP {response.status_code}"
                    )
                    
            except Exception as e:
                if attempt < retry_count - 1:
                    logger.debug(f"Error on attempt {attempt + 1}: {e}")
                    time.sleep(2)
                    continue
                return CheckResult(
                    address=address,
                    boost_eligible=False,
                    airdrop_eligible=False,
                    boost_rate=0,
                    tier_name='ERROR',
                    airdrop_allocation=None,
                    error=str(e)
                )
        
        return CheckResult(
            address=address,
            boost_eligible=False,
            airdrop_eligible=False,
            boost_rate=0,
            tier_name='ERROR',
            airdrop_allocation=None,
            error="Max retries exceeded"
        )


def load_file(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"File {filepath} not found")
        sys.exit(1)


def print_result(result: CheckResult, index: int, total: int):
    short_addr = f"{result.address[:10]}...{result.address[-6:]}"
    
    if result.error:
        logger.warning(f"[{index}/{total}] {short_addr} - ERROR: {result.error}")
        return
    
    status_parts = []
    
    if result.airdrop_eligible:
        alloc_str = f" (Allocation: {result.airdrop_allocation})" if result.airdrop_allocation else ""
        status_parts.append(f"AIRDROP ELIGIBLE{alloc_str}")
    
    if result.boost_eligible:
        status_parts.append(f"BOOST ELIGIBLE - {result.tier_name} ({result.boost_rate*100:.0f}%)")
    
    if status_parts:
        logger.success(f"[{index}/{total}] {short_addr} - {', '.join(status_parts)}")
    else:
        logger.info(f"[{index}/{total}] {short_addr} - NOT ELIGIBLE")


def print_summary(results: List[CheckResult]):
    total = len(results)
    boost_eligible = sum(1 for r in results if r.boost_eligible)
    airdrop_eligible = sum(1 for r in results if r.airdrop_eligible)
    errors = sum(1 for r in results if r.error)
    
    tiers = {}
    for r in results:
        if not r.error and r.boost_eligible:
            tiers[r.tier_name] = tiers.get(r.tier_name, 0) + 1
    
    logger.info("=" * 70)
    logger.info("SUMMARY STATISTICS")
    logger.info("=" * 70)
    logger.info(f"Total checked:       {total}")
    logger.info(f"Boost eligible:      {boost_eligible} ({boost_eligible/total*100:.1f}%)")
    logger.info(f"Airdrop eligible:    {airdrop_eligible} ({airdrop_eligible/total*100:.1f}%)")
    logger.info(f"Errors:              {errors}")
    
    if tiers:
        logger.info("Tier distribution:")
        for tier, count in sorted(tiers.items()):
            logger.info(f"  {tier}: {count}")
    
    airdrop_addresses = [r.address for r in results if r.airdrop_eligible]
    if airdrop_addresses:
        logger.success("Addresses with airdrop:")
        for addr in airdrop_addresses:
            result = next(r for r in results if r.address == addr)
            alloc = f" - {result.airdrop_allocation} ALLO" if result.airdrop_allocation else ""
            logger.success(f"  {addr}{alloc}")
    
    logger.info("=" * 70)


def main():
    logger.info("=" * 70)
    logger.info("ALLORA PRIME AIRDROP CHECKER")
    logger.info("=" * 70)
    
    addresses = load_file('addresses.txt')
    proxies = load_file('proxies.txt')
    
    logger.info(f"Loaded {len(addresses)} addresses")
    logger.info(f"Loaded {len(proxies)} proxies")
    
    if len(proxies) < len(addresses):
        logger.warning("Proxies count < addresses count, will reuse proxies")
    
    checker = AlloraChecker()
    results = []
    lock = Lock()
    
    logger.info("Starting checks...")
    
    max_workers = min(10, len(addresses))
    
    def check_with_index(i, address):
        proxy = proxies[(i-1) % len(proxies)] if proxies else None
        result = checker.check_address(address, proxy)
        
        with lock:
            results.append(result)
            print_result(result, i, len(addresses))
        
        return result
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_with_index, i, addr): i 
                   for i, addr in enumerate(addresses, 1)}
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Thread error: {e}")
    
    results.sort(key=lambda x: addresses.index(x.address))
    
    print_summary(results)
    
    with open('results.csv', 'w') as f:
        f.write("address,boost_eligible,airdrop_eligible,tier,boost_rate,airdrop_allocation,error\n")
        for r in results:
            alloc = r.airdrop_allocation if r.airdrop_allocation else ""
            f.write(f"{r.address},{r.boost_eligible},{r.airdrop_eligible},{r.tier_name},{r.boost_rate},{alloc},{r.error or ''}\n")
    
    logger.success("Results saved to results.csv")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Critical error: {e}")
        sys.exit(1)
