echo "Starting certname script." > certname.log
cd "%~dp0"
call environment.bat
echo "Called environment.bat." >> certname.log
call gem install hashie
call gem install inifile
echo "Installed gems, calling puppet_certname.rb" >> certname.log
cmd.exe /c ruby puppet_certname.rb
echo "Called ruby." >> certname.log
puppet agent -t
echo "Called puppet agent." >> certname.log
