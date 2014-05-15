@echo off
cd "%~dp0"
call environment.bat
gem install hashie
gem install inifile
ruby puppet_certname.rb
