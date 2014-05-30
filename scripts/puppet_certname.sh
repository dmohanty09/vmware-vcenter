#!/bin/bash

VERSION=`puppet --version`

if [[ "$VERSION" =~ Enterprise ]]
then
  /opt/puppet/bin/gem install hashie
  /opt/puppet/bin/gem install inifile
  /opt/puppet/bin/ruby puppet_certname.rb
else
  gem install hashie
  gem install inifile
  ruby puppet_certname.rb
fi
