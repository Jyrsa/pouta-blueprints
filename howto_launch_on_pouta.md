# How to launch Pouta Blueprints server on cPouta

These are step by step instructions on how to launch a Pouta Blueprints server on 
cPouta IaaS cloud (https://research.csc.fi/pouta-iaas-cloud). We assume that you are
familiar with the cPouta service. Horizon web interface will be used as an example.

First we create a security group, then launch a server and finally install the software
using ssh interactive session.

# Part 1: Launch the server

## Prerequisites

* First log in to https://pouta.csc.fi

* Check that quota on the first page looks ok.

* Upload public key or create a key pair, if you have not done so already (Access and Security -> Key Pairs)

## Create a security group for the server

* In case you are a member of multiple projects in cPouta, select the desired project in the project selection 
  drop down box on the top of the page 

* Create a security group called 'pb_server' for the server (Access and Security -> Create Security Group )

* Add ssh and https -access to your workstation IP/subnet (Manage rules -> Add rule) 
  * ssh: port 22, CIDR: your ip/32 (you can check your ip with e.g. http://www.whatismyip.com/)
  * https: port 443, CIDR: like above

## Boot the server

* Go to (Instances -> Launch Instance)

* Details tab:
  * Instance name: e.g. 'pb_server'
  * Flavor: mini
  * Instance boot source: boot from image, Image: Ubuntu-14.04

* Access and security tab:
  * Key Pair: your keypair
  * Security Groups: unselect 'default', select 'pb_server'
  
* Networks tab: default network is ok.

* Post-Creation and Advanced tabs can be skipped

## Assign a public IP

* Go to (Instances) and click More on pb_server instance row. Select 'Associate floating IP'

* Select a free floating IP from the list and click 'Associate' 

* If there are no items in the list, allocate an address with (+). 
 

## Download machine to machine OpenStack RC -file

* Log out and log in to https://pouta.csc.fi again, this time using your machine to machine credentials

* Go to (Access and Security -> API Access) and click 'Download OpenStack RC File'. Save the file to a known location
  on your local computer
  
# Part 2: Install software

Open ssh connection to the server::

    $ ssh cloud-user@<public ip of the server>

Clone the repository from GitHub::

    $ sudo apt-get install -y git
    $ git clone --branch v1.2 https://github.com/CSC-IT-Center-for-Science/pouta-blueprints.git

Run the install script once - you will asked to log out and in again to make unix group changes effective. 

    $ ./pouta-blueprints/scripts/install_pb.bash
    $ logout    

Now that you know that ssh works, copy the m2m OpenStack RC file to the server

    $ scp path/to/your/saved/rc-file.bash cloud-user@<public ip of the server>:

SSH in again, source the OpenStack credentials and continue installation

    $ ssh cloud-user@<public ip of the server>
    $ source your-openrc.bash
    $ ./pouta-blueprints/scripts/install_pb.bash

Final task is to configure the outgoing mail settings. Create a file called /etc/pouta_blueprints/config.yaml.local 
in both containers with the following contents::

    SENDER_EMAIL: 'your.valid.email@example.org'
    MAIL_SERVER: 'server.assigned.to.you.by.csc'
    MAIL_SUPPRESS_SEND: False
    
Running nano/vim in each of the containers:: 
    
    ssh www/worker
    sudo vim /etc/pouta_blueprints/config.yaml.local 

# Part 3: Start using the software

The installation script will print out initialization URL at the end of the installation. Navigate to that, set the
admin credentials and start using the system.
 
Link to User Guide: TBA

# Part 4: Open access to users

TBA

# Part 5: Administrative tasks and troubleshooting

(backing up the central database, cleaning misbehaving VMs and other resources, ...)

TBA 


# Notes on container based deployment

The default installation with the provided script make a Docker container based deployment. Since the system will have
OpenStack credentials for the project it is serving and also be exposed to internet, we have an extra layer of isolation
between http server and provisioning processes holding the credentials. The processes are not containerized more than 
necessary to achieve this, so you can think of the containers as mini virtual machines.

There are two containers, www and worker. You can list the status with::

    $ docker ps
    $ docker ps -a
    
Aliases are provided for an easy ssh access::

    $ ssh worker
    $ ssh www

Both of the containers share the git repository that was checked out during installation through a read only shared 
folder. Worker also has an additional shared folder for the credentials stored on the ramdisk on the host machine.

To see the server process logs, take a look at /webapps/pouta_blueprints/logs -directory in the container::

    $ ssh www
    $ ls /webapps/pouta_blueprints/logs

Currently the system has a known limitation of not starting containers automatically at boot, see [1] and [2]. 
To manually start the services, you can run the installation procedure again. That will start the containers and 
server processes plus place a copy of the credentials on the ramdisk. In the future, only the credentials part will
be needed.

[1]: https://github.com/CSC-IT-Center-for-Science/pouta-blueprints/issues/82

[2]: https://github.com/CSC-IT-Center-for-Science/pouta-blueprints/issues/84