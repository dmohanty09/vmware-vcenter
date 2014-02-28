ASM Deployer
============

This module contains a sinatra app to deploy ASM service templates. It
currently runs within torquebox on the ASM appliance.

The asm-deployer service translates the ASM ServiceTemplate
data-structure into calls to the puppet asm command provided by the
[asm module][1]. For more details on that process see the [asm module][1]
README and the confluence wiki page [ServiceTemplate Deployment Process][2].

REST services currently provided are:

    POST http://localhost:8080/asm/process_service_profile

Initiates a service deployment. See spec/fixtures/asm_server_m620.json and other files in that directory for sample payloads. Logs for the deployment are stored under /opt/Dell/ASM/deployments/`DEPLOYMENT_ID`.

    GET http://localhost:8080/asm/logs/`DEPLOYMENT_ID`

Retrieves logs related to a deployment.

[1]: https://github.com/dell-asm/asm "Puppet ASM Module"
[2]: https://confluence.kace.com/display/ASM/Service+Template+Deployment+Processing "Service Template Deployment Processing"

Developer Setup
---------------

The following instructions are specific for running and developing the
asm-deployer service on the ASM appliance build. asm-deployer is
currently being run in torquebox which provides sinatra and rails
integration on top of JBoss with JRuby.

    # From top-level checkout, make asm-deployer/lib classes available
    export RUBYLIB=lib
    
    # Set up http proxy
    export http_proxy=http://proxy.us.dell.com:80
    export https_proxy=http://proxy.us.dell.com:80
    
    # Install gems necessary to run tests (only needed once)
    gem install puppet
    gem install puppetlabs_spec_helper

Deployment
----------

If any files are changed under asm-deployer, the module must be
re-deployed to torquebox in order to make those changes available on
the web service at `http://localhost:8080`. This is analagous to
deploying a war in Tomcat.

    # From the checkout directory (asm-deployer)
    torquebox deploy

Testing
-------

The unit tests are run with rspec.

    rspec

Deployments can be tested by POSTing deployment json data to the
deployment service. This example uses curl to POST the
spec/fixtures/test_data.json file to the service:

    curl -X POST -H "Content-Type: application/json" -d @spec/fixtures/test_data.json http://localhost:8081/asm/process_service_profile

It may be necessary to clean up files out of /opt/Dell/ASM/deployments
and/or /etc/puppetlabs/puppet/node_data after running a test in order
to run them again.
