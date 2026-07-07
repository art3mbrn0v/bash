#!/bin/bash
set -e

echo "=== LightDM Look & Feel Fixer & Improver ==="

# Run the python script to check status
set +e
python3 /home/artem/configure_lightdm_fixed.py
STATUS=$?
set -e

if [ $STATUS -eq 2 ]; then
    echo "Restoring default lightdm.conf from repository package..."
    sudo rm -f /etc/lightdm/lightdm.conf
    sudo apt-get install -y -o Dpkg::Options::="--force-confmiss" --reinstall lightdm
    
    echo "Running configuration script again..."
    sudo python3 /home/artem/configure_lightdm_fixed.py
elif [ $STATUS -eq 0 ]; then
    echo "lightdm.conf is in a good state."
else
    echo "Python script failed with error code $STATUS. Retrying configuration after forced package reinstall..."
    sudo rm -f /etc/lightdm/lightdm.conf
    sudo apt-get install -y -o Dpkg::Options::="--force-confmiss" --reinstall lightdm
    sudo python3 /home/artem/configure_lightdm_fixed.py
fi

echo "Copying Slick Greeter configuration..."
sudo cp /home/artem/slick-greeter.conf /etc/lightdm/slick-greeter.conf
sudo chmod 644 /etc/lightdm/slick-greeter.conf

# Ensure wallpaper is in the right place and readable
echo "Ensuring wallpaper exists and is readable..."
sudo mkdir -p /usr/share/backgrounds
sudo cp /home/artem/Pictures/wallpaper-bladerunner2049.png /usr/share/backgrounds/
sudo chmod 644 /usr/share/backgrounds/wallpaper-bladerunner2049.png

echo "Checking configurations..."
echo "--- /etc/lightdm/slick-greeter.conf ---"
cat /etc/lightdm/slick-greeter.conf
echo "---------------------------------------"

echo "=== Done! Configuration applied. ==="
echo "To test the login screen in a window, run: lightdm --test-mode"
echo "To make it active, restart lightdm (sudo systemctl restart lightdm) or reboot."
