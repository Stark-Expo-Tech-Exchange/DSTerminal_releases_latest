Package: dsterminal
Version: 2.00.00
Section: security
Priority: optional
Architecture: all
Maintainer: Spark Wilson Spink <spark@starkexpo.tech>
Depends: python3, python3-pip, python3-venv, git
Description: Defensive Security Terminal
 Advanced CLI security toolkit for system hardening and monitorin>
Homepage: https://github.com/Stark-Expo-Tech-Exchange/DSTerminal.git>


<!-- SCRIPT FOR BUILDING & PACKAGING TO .DEB INSTALLABLE SOFTWARE =====STARTS HERE -->
mkdir -p ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb/DEBIAN
mkdir -p ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb/usr/local/bin
nano ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb/DEBIAN/control

<!-- THEN FOUTH STEP HERE -->
pyinstaller --onefile --console --icon=icon.ico dsterminal.py -n dsterminal

cp ~/Desktop/DSTerminal/dist/dsterminal ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb/usr/local/bin/

chmod +x ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb/usr/local/bin/dsterminal 

dpkg-deb --build ~/dsterminal_starkterminal_tool.v2.0.0.2024_deb
sudo dpkg -i ~/dsterminal_starkterminal_tool.v2.0.2024_deb.deb
dsterminal 

<!-- OR -->
sudo dsterminal 
