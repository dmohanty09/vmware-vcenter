@echo off
cd "%~dp0"
call environment.bat
call gem install hashie
call gem install inifile
ruby puppet_certname.rb
