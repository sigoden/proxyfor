pandoc assets/install-certificate.md -o assets/install-certificate.html
sed -i -e 's|<!-- ||' -e 's| -->||' assets/install-certificate.html