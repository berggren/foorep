### Ubuntu 12.04
1. Install mongodb  
`$ sudo apt-get install mongodb`  
2. Install support for parsing exif    
`$ sudo apt-get install python-pyexiv2`  
3. Install foorep  
`$ sudo pip install foorep`

***

### Ubuntu 10.04 and SIFT Workstation 2.14 (Ubuntu 9.10)
The provided version of mongodb in older Ubuntu is lacking some features that foorep depends on.
Because of this we need to install mongodb from 10gens repository.

1. Uninstall old mongodb  
`$ sudo apt-get remove mongodb`  
2. Add 10gen Ubuntu repository to sources.list  
`$ sudo echo "deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen" >> /etc/apt/sources.list`  
3. Add 10gen key  
`$ sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 7F0CEB10`
4. Update apt  
`$ sudo apt-get update`  
5. Install mongodb  
`$ sudo apt-get install mongodb-10gen`  
6. Install support for parsing exif  
`$ sudo apt-get install python-pyexiv2`  
7. Remove python-magic, the version bundled with Ubuntu is too old.  
`$ sudo apt-get remove python-magic`  
8. Install foorep  
`$ sudo pip install foorep`  
