#!/usr/bin/env python3
"""
Portly Server - Port Forwarding as a Service
Main Flask application for managing WireGuard tunnels
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import secrets
import ipaddress
import os
import json
from functools import wraps
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Configuration
CONFIG_FILE = '/etc/portly/config.json'
WG_INTERFACE = 'wg0'
TUNNEL_NETWORK = '192.169.66.0/24'
PORT_RANGE_START = 10000
PORT_RANGE_END = 60000
SERVER_PUBLIC_IP = None  # Will be auto-detected

# Initialize configuration
def init_config():
    """Initialize configuration file"""
    os.makedirs('/etc/portly', exist_ok=True)
    
    if not os.path.exists(CONFIG_FILE):
        config = {
            'api_keys': {},
            'services': {},
            'ip_leases': {},
            'port_assignments': {},
            'server_private_key': generate_private_key(),
            'server_public_key': None,
            'next_ip': 2,  # Start from .2 (.1 is the server)
            'created_at': datetime.now().isoformat()
        }
        
        # Generate server public key
        config['server_public_key'] = get_public_key(config['server_private_key'])
        
        save_config(config)
        return config
    
    return load_config()

def load_config():
    """Load configuration from file"""
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_config(config):
    """Save configuration to file"""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        config = load_config()
        
        if not api_key or api_key not in config['api_keys']:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Add user_id to request context
        request.user_id = config['api_keys'][api_key]
        return f(*args, **kwargs)
    
    return decorated_function

def generate_private_key():
    """Generate WireGuard private key"""
    result = subprocess.run(['wg', 'genkey'], capture_output=True, text=True)
    return result.stdout.strip()

def get_public_key(private_key):
    """Get public key from private key"""
    result = subprocess.run(
        ['wg', 'pubkey'],
        input=private_key,
        capture_output=True,
        text=True
    )
    return result.stdout.strip()

def get_server_public_ip():
    """Get server's public IP address"""
    global SERVER_PUBLIC_IP
    if SERVER_PUBLIC_IP:
        return SERVER_PUBLIC_IP
    
    try:
        result = subprocess.run(
            ['curl', '-s', 'ifconfig.me'],
            capture_output=True,
            text=True,
            timeout=5
        )
        SERVER_PUBLIC_IP = result.stdout.strip()
        return SERVER_PUBLIC_IP
    except:
        return '0.0.0.0'

def allocate_ip():
    """Allocate next available IP address"""
    config = load_config()
    network = ipaddress.IPv4Network(TUNNEL_NETWORK)
    
    ip_num = config['next_ip']
    ip = str(network.network_address + ip_num)
    
    config['next_ip'] += 1
    save_config(config)
    
    return ip

def allocate_port():
    """Allocate next available public port"""
    config = load_config()
    used_ports = set(config['port_assignments'].keys())
    
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if str(port) not in used_ports:
            return port
    
    raise Exception("No available ports")

def add_firewall_rule(public_port, tunnel_ip, local_port, protocol='tcp'):
    """Add iptables rule to forward traffic"""
    # Enable IP forwarding
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)
    
    # Add PREROUTING rule for DNAT
    subprocess.run([
        'iptables', '-t', 'nat', '-A', 'PREROUTING',
        '-p', protocol,
        '--dport', str(public_port),
        '-j', 'DNAT',
        '--to-destination', f'{tunnel_ip}:{local_port}'
    ], check=True)
    
    # Add FORWARD rule
    subprocess.run([
        'iptables', '-A', 'FORWARD',
        '-p', protocol,
        '-d', tunnel_ip,
        '--dport', str(local_port),
        '-j', 'ACCEPT'
    ], check=True)
    
    # Add POSTROUTING rule for SNAT
    subprocess.run([
        'iptables', '-t', 'nat', '-A', 'POSTROUTING',
        '-p', protocol,
        '-d', tunnel_ip,
        '--dport', str(local_port),
        '-j', 'MASQUERADE'
    ], check=True)

def remove_firewall_rule(public_port, tunnel_ip, local_port, protocol='tcp'):
    """Remove iptables rules"""
    try:
        subprocess.run([
            'iptables', '-t', 'nat', '-D', 'PREROUTING',
            '-p', protocol,
            '--dport', str(public_port),
            '-j', 'DNAT',
            '--to-destination', f'{tunnel_ip}:{local_port}'
        ])
        
        subprocess.run([
            'iptables', '-D', 'FORWARD',
            '-p', protocol,
            '-d', tunnel_ip,
            '--dport', str(local_port),
            '-j', 'ACCEPT'
        ])
        
        subprocess.run([
            'iptables', '-t', 'nat', '-D', 'POSTROUTING',
            '-p', protocol,
            '-d', tunnel_ip,
            '--dport', str(local_port),
            '-j', 'MASQUERADE'
        ])
    except:
        pass  # Rules might not exist

def add_wireguard_peer(public_key, tunnel_ip):
    """Add peer to WireGuard interface"""
    subprocess.run([
        'wg', 'set', WG_INTERFACE,
        'peer', public_key,
        'allowed-ips', f'{tunnel_ip}/32'
    ], check=True)

def remove_wireguard_peer(public_key):
    """Remove peer from WireGuard interface"""
    try:
        subprocess.run([
            'wg', 'set', WG_INTERFACE,
            'peer', public_key,
            'remove'
        ])
    except:
        pass

# API Routes

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user and get API key"""
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    config = load_config()
    
    # Check if username exists
    if username in config['api_keys'].values():
        return jsonify({'error': 'Username already exists'}), 400
    
    # Generate API key
    api_key = secrets.token_urlsafe(32)
    config['api_keys'][api_key] = username
    save_config(config)
    
    return jsonify({
        'api_key': api_key,
        'username': username,
        'message': 'Registration successful. Save your API key securely!'
    })

@app.route('/api/services', methods=['GET'])
@require_api_key
def get_services():
    """Get all services for the authenticated user"""
    config = load_config()
    user_services = []
    
    for service_id, service in config['services'].items():
        if service['user_id'] == request.user_id:
            user_services.append({
                'id': service_id,
                **service
            })
    
    return jsonify({'services': user_services})

@app.route('/api/services', methods=['POST'])
@require_api_key
def create_service():
    """Create a new service tunnel"""
    data = request.get_json()
    
    name = data.get('name')
    local_port = data.get('local_port')
    protocol = data.get('protocol', 'tcp')
    
    if not name or not local_port:
        return jsonify({'error': 'Name and local_port required'}), 400
    
    try:
        config = load_config()
        
        # Generate service ID
        service_id = secrets.token_urlsafe(16)
        
        # Allocate resources
        tunnel_ip = allocate_ip()
        public_port = allocate_port()
        
        # Generate client keys
        client_private_key = generate_private_key()
        client_public_key = get_public_key(client_private_key)
        
        # Create service record
        service = {
            'user_id': request.user_id,
            'name': name,
            'local_port': local_port,
            'public_port': public_port,
            'tunnel_ip': tunnel_ip,
            'protocol': protocol,
            'client_private_key': client_private_key,
            'client_public_key': client_public_key,
            'active': False,
            'created_at': datetime.now().isoformat()
        }
        
        # Save to config
        config['services'][service_id] = service
        config['ip_leases'][tunnel_ip] = service_id
        config['port_assignments'][str(public_port)] = service_id
        save_config(config)
        
        # Add WireGuard peer
        add_wireguard_peer(client_public_key, tunnel_ip)
        
        # Add firewall rules
        add_firewall_rule(public_port, tunnel_ip, local_port, protocol)
        
        # Mark as active
        config = load_config()
        config['services'][service_id]['active'] = True
        save_config(config)
        
        return jsonify({
            'message': 'Service created successfully',
            'service': {
                'id': service_id,
                **service
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/services/<service_id>', methods=['DELETE'])
@require_api_key
def delete_service(service_id):
    """Delete a service tunnel"""
    config = load_config()
    
    if service_id not in config['services']:
        return jsonify({'error': 'Service not found'}), 404
    
    service = config['services'][service_id]
    
    # Verify ownership
    if service['user_id'] != request.user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Remove firewall rules
        remove_firewall_rule(
            service['public_port'],
            service['tunnel_ip'],
            service['local_port'],
            service['protocol']
        )
        
        # Remove WireGuard peer
        remove_wireguard_peer(service['client_public_key'])
        
        # Remove from config
        del config['services'][service_id]
        del config['ip_leases'][service['tunnel_ip']]
        del config['port_assignments'][str(service['public_port'])]
        save_config(config)
        
        return jsonify({'message': 'Service deleted successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['GET'])
@require_api_key
def get_client_config():
    """Generate WireGuard client configuration"""
    config = load_config()
    user_services = [s for s in config['services'].values() 
                     if s['user_id'] == request.user_id]
    
    if not user_services:
        return jsonify({'error': 'No services configured'}), 404
    
    # Use the first service's keys (or combine if needed)
    service = user_services[0]
    
    server_ip = get_server_public_ip()
    network = ipaddress.IPv4Network(TUNNEL_NETWORK)
    server_tunnel_ip = str(network.network_address + 1)
    
    client_config = f"""[Interface]
PrivateKey = {service['client_private_key']}
Address = {service['tunnel_ip']}/32
DNS = 1.1.1.1

[Peer]
PublicKey = {config['server_public_key']}
Endpoint = {server_ip}:51820
AllowedIPs = {server_tunnel_ip}/32
PersistentKeepalive = 25
"""
    
    return jsonify({'config': client_config})

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get server status (public endpoint)"""
    try:
        # Get WireGuard status
        result = subprocess.run(['wg', 'show', WG_INTERFACE], 
                              capture_output=True, text=True)
        wg_status = 'running' if result.returncode == 0 else 'stopped'
    except:
        wg_status = 'error'
    
    config = load_config()
    
    return jsonify({
        'status': 'online',
        'wireguard': wg_status,
        'total_services': len(config['services']),
        'available_ports': PORT_RANGE_END - PORT_RANGE_START - len(config['port_assignments'])
    })

if __name__ == '__main__':
    # Initialize configuration
    init_config()
    
    # Run server
    app.run(host='0.0.0.0', port=5000, debug=False)