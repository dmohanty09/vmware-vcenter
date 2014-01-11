ASM Deployer
============

This module contains a sinatra app to deploy ASM service templates.

Requires:

    [root@dellasm ~]# mkdir /opt/Dell/ASM/deployments
    [root@dellasm ~]# chown razor:razor /opt/Dell/ASM/deployments

Allow razor to use sudo puppet

Allow razor to create deployments directory under /opt/Dell/ASM:

    chown tomcat:razor /opt/Dell/ASM
    chmod 775 /opt/Dell/ASM
