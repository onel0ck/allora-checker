#!/usr/bin/env python3

import requests
import time
import base64
import hashlib
import json
from typing import Optional, List, Tuple
from dataclasses import dataclass
import sys
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from Crypto.Hash import RIPEMD160
import bech32
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize

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


class CosmosWallet:

    @staticmethod
    def from_mnemonic(mnemonic: str) -> Tuple[str, str, bytes]:
        seed = Bip39SeedGenerator(mnemonic).Generate()

        bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.COSMOS)
        bip44_acc = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)

        pubkey_compressed = bip44_acc.PublicKey().RawCompressed().ToBytes()
        privkey_bytes = bip44_acc.PrivateKey().Raw().ToBytes()

        sha256_hash = hashlib.sha256(pubkey_compressed).digest()
        h = RIPEMD160.new()
        h.update(sha256_hash)
        ripemd160_hash = h.digest()

        converted = bech32.convertbits(ripemd160_hash, 8, 5)
        address = bech32.bech32_encode('allo', converted)

        pubkey_base64 = base64.b64encode(pubkey_compressed).decode()

        return address, pubkey_base64, privkey_bytes

    @staticmethod
    def sign_arbitrary(privkey_bytes: bytes, signer: str, data: bytes) -> str:
        sign_doc = {
            "chain_id": "",
            "account_number": "0",
            "sequence": "0",
            "fee": {
                "gas": "0",
                "amount": []
            },
            "msgs": [
                {
                    "type": "sign/MsgSignData",
                    "value": {
                        "signer": signer,
                        "data": base64.b64encode(data).decode()
                    }
                }
            ],
            "memo": ""
        }

        sign_bytes = json.dumps(sign_doc, separators=(',', ':'), sort_keys=True).encode()

        msg_hash = hashlib.sha256(sign_bytes).digest()

        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        signature = sk.sign_digest(msg_hash, sigencode=sigencode_string_canonize)

        return base64.b64encode(signature).decode()


class AlloraChecker:
    def __init__(self):
        self.url = "https://prime.allora.foundation/api/upshot-api-proxy/allora/prime/check-program-allocation"
        self.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/json',
            'origin': 'https://prime.allora.foundation',
            'referer': 'https://prime.allora.foundation/check-eligibility',
            'sec-ch-ua': '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

    def check_address(self, address: str, signature: str, pubkey: str,
                     proxy: Optional[str] = None, retry_count: int = 3) -> CheckResult:
        for attempt in range(retry_count):
            try:
                proxies = None
                if proxy:
                    proxies = {
                        'http': proxy,
                        'https': proxy
                    }

                payload = {
                    "wallet": {
                        "address": address,
                        "signature": signature,
                        "public_key": pubkey
                    }
                }

                response = requests.post(
                    self.url,
                    headers=self.headers,
                    json=payload,
                    proxies=proxies,
                    timeout=30
                )

                if response.status_code in [200, 201]:
                    data = response.json()

                    if data.get('status') and 'data' in data:
                        result_data = data['data']
                        tier = result_data.get('current_tier') or result_data.get('default_tier') or {}

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
                        error=f"HTTP {response.status_code}: {response.text[:100]}"
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


def load_seeds(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as f:
            seeds = []
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    seeds.append(line)
            return seeds
    except FileNotFoundError:
        logger.error(f"File {filepath} not found")
        sys.exit(1)


def load_proxies(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.warning(f"File {filepath} not found, will work without proxies")
        return []


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
    logger.info("ALLORA PRIME AIRDROP CHECKER V5")
    logger.info("=" * 70)

    seeds = load_seeds('seeds.txt')
    proxies = load_proxies('proxies.txt')

    logger.info(f"Loaded {len(seeds)} seed phrases")
    logger.info(f"Loaded {len(proxies)} proxies")

    if proxies and len(proxies) < len(seeds):
        logger.warning("Proxies count < seeds count, will reuse proxies")

    logger.info("Generating wallets and signatures from seeds...")

    wallets = []
    for i, seed in enumerate(seeds, 1):
        try:
            address, pubkey, privkey = CosmosWallet.from_mnemonic(seed)

            message_bytes = address.encode('utf-8')
            signature = CosmosWallet.sign_arbitrary(privkey, address, message_bytes)

            wallets.append((address, signature, pubkey))
            logger.debug(f"Generated wallet {i}/{len(seeds)}: {address[:10]}...")
        except Exception as e:
            logger.error(f"Failed to generate wallet from seed {i}: {e}")
            continue

    logger.info(f"Generated {len(wallets)} wallets")

    checker = AlloraChecker()
    results = []
    lock = Lock()

    logger.info("Starting checks...")

    max_workers = min(10, len(wallets))

    def check_with_index(i, wallet):
        address, signature, pubkey = wallet
        proxy = proxies[(i-1) % len(proxies)] if proxies else None
        result = checker.check_address(address, signature, pubkey, proxy)

        with lock:
            results.append(result)
            print_result(result, i, len(wallets))

        return result

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_with_index, i, wallet): i
                   for i, wallet in enumerate(wallets, 1)}

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Thread error: {e}")

    wallet_addresses = [w[0] for w in wallets]
    results.sort(key=lambda x: wallet_addresses.index(x.address))

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
