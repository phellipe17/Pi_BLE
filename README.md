# Pi_BLE

# requiriments to install and run connection bluetooth with python3 on raspberry pi 3b:

pip3 install bleak
pip3 install tinyec
pip3 install pycryptodome

# Add policy in bluetooth conf:

sudo nano /etc/dbus-1/system.d/bluetooth.conf

<policy user="pi">
    <allow send_destination="org.bluez"/>
    <allow own="org.bluez"/>
    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>
</policy>

# After this alterantions restart bluetooth and dbus

sudo systemctl restart bluetooth
sudo systemctl restart dbus