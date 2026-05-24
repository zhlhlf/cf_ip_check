#!/usr/bin/env python3
"""
Cloudflare IP优选工具
输出格式: IP:端口#国家代码 官方优选 延迟ms
"""

import ipaddress
import random
import socket
import time
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

def fetch_cidrs(url: str) -> List[str]:
    """从远程URL获取CIDR列表"""
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        cidrs = [line.strip() for line in resp.text.splitlines() 
                 if line.strip() and not line.startswith('#')]
        print(f"✓ 获取到 {len(cidrs)} 个CIDR网段")
        return cidrs
    except Exception as e:
        print(f"✗ 获取CIDR失败: {e}")
        fallback = [
            "108.162.198.0/24", "172.64.144.0/22", "104.18.32.0/20",
            "162.159.32.0/20", "173.245.58.0/23", "104.26.0.0/20"
        ]
        print(f"⚠ 使用备选 {len(fallback)} 个CIDR网段")
        return fallback

def ip_from_cidr(cidr: str) -> str:
    """从CIDR中随机生成一个IP地址"""
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    if not hosts:
        return str(network.network_address)
    return str(random.choice(hosts))

def test_endpoint(ip: str, port: int, timeout: float) -> Tuple[str, float, bool]:
    """测试TCP连接延迟"""
    try:
        start = time.time()
        with socket.create_connection((ip, port), timeout=timeout):
            elapsed = (time.time() - start) * 1000
            return ip, elapsed, True
    except Exception:
        return ip, float('inf'), False

def get_country_code(ip: str) -> Tuple[str, str]:
    """通过 ip9.com.cn 获取国家代码，返回 (ip, code)"""
    try:
        resp = requests.get(f"https://ip9.com.cn/get?ip={ip}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('ret') == 200:
                code = data.get('data', {}).get('country_code', 'xx')
                return ip, code.upper()
    except:
        pass
    return ip, 'XX'

def generate_candidate_ips(cidr_list: List[str], sample_size: int = 200) -> List[str]:
    """生成候选IP"""
    if sample_size <= 0 or not cidr_list:
        return []

    networks = []
    total_weight = 0
    for cidr in cidr_list:
        network = ipaddress.ip_network(cidr, strict=False)
        host_count = max(1, network.num_addresses - 2)
        networks.append((cidr, host_count))
        total_weight += host_count

    quotas = []
    assigned = 0
    for cidr, host_count in networks:
        quota = max(1, int(sample_size * host_count / total_weight))
        quotas.append([cidr, quota])
        assigned += quota

    idx = 0
    while assigned < sample_size:
        quotas[idx % len(quotas)][1] += 1
        assigned += 1
        idx += 1

    ips = []
    for cidr, quota in quotas:
        for _ in range(quota):
            ips.append(ip_from_cidr(cidr))
    
    random.shuffle(ips)
    return ips[:sample_size]

def main():
    parser = argparse.ArgumentParser(description="Cloudflare IP优选工具")
    parser.add_argument("--count", type=int, default=32, help="输出最优IP数量")
    parser.add_argument("--port", type=int, default=2096, help="测试端口")
    parser.add_argument("--timeout", type=float, default=2.0, help="连接超时秒数")
    parser.add_argument("--samples", type=int, default=512, help="测试IP样本数量")
    parser.add_argument("--threads", type=int, default=50, help="并发线程数")
    args = parser.parse_args()

    print(f"\n🚀 开始优选 - 端口: {args.port}\n")
    
    cidr_url = "https://ghfast.top/raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt"
    cidrs = fetch_cidrs(cidr_url)
    
    candidate_ips = generate_candidate_ips(cidrs, args.samples)
    print(f"📡 生成 {len(candidate_ips)} 个候选IP，开始测试...\n")
    
    # 测试TCP连接
    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_ip = {
            executor.submit(test_endpoint, ip, args.port, args.timeout): ip 
            for ip in candidate_ips
        }
        
        completed = 0
        for future in as_completed(future_to_ip):
            ip, delay, success = future.result()
            completed += 1
            if success:
                results.append((ip, delay))
                print(f"✓ [{completed}/{len(candidate_ips)}] {ip}:{args.port} - {delay:.0f}ms")
            else:
                print(f"✗ [{completed}/{len(candidate_ips)}] {ip}:{args.port} - 超时")
    
    # 排序
    results.sort(key=lambda x: x[1])
    best_ips = results[:args.count]
    
    # 并发获取地理位置
    # print(f"\n🌍 并发获取地理位置 ({len(best_ips)}个)...")
    # ip_to_code = {}
    # with ThreadPoolExecutor(max_workers=20) as executor:
    #     futures = [executor.submit(get_country_code, ip) for ip, _ in best_ips]
    #     for future in as_completed(futures):
    #         ip, code = future.result()
    #         ip_to_code[ip] = code
    
    # 输出结果
    print(f"\n✨ 优选结果:\n")
    output_lines = []
    for ip, delay in best_ips:
        # code = ip_to_code.get(ip, 'XX')
        line = f"{ip}:{args.port}# {delay:.0f}ms"
        output_lines.append(line)
        print(line)
    
    # 保存
    # with open("optimized_ips.txt", "w", encoding='utf-8') as f:
    #     f.write("\n".join(output_lines))
    
    # print(f"\n💾 保存到 optimized_ips.txt")

if __name__ == "__main__":
    main()