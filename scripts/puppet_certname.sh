#!/bin/bash

VERSION=`puppet --version`

if [[ "$VERSION" =~ Enterprise ]]
then
  /opt/puppet/bin/gem install hashie
  /opt/puppet/bin/gem install inifile
  /opt/puppet/bin/ruby puppet_certname.rb
  /opt/puppet/bin/puppet agent -t
else
  gem install hashie
  gem install inifile
  ruby /usr/local/bin/puppet_certname.rb
  puppet agent -t
fi
