class Blade_server_switch_information

  def initialize(servicetag,serverinfo,swinfo)
    @nodename=servicetag
    @sinfo=serverinfo
    @switchinfo=swinfo
  end
  
  def identify_switch_ports
    serviceTag=@nodename
    serverModel=@sinfo['server_model']
    idracIp=@sinfo['idrac_ip']
    idracusername=@sinfo['idrac_username']
    idracpassword=@sinfo['idrac_password']
    chassisip=@sinfo['chassis_ip']
    chassisusername=@sinfo['chassis_username']
    chassispassword=@sinfo['chassis_password']
    slot=@sinfo['slot_num']
    
    quaterBladeModelList = [ "M420" ]
    halfBladeModelList = [ "M620" ]
    fullBladeModelList = [ "M820" ]
    out = `racadm -r  #{chassisip} -u #{chassisusername} -p #{chassispassword} getioinfo`
    switchlist = []
    retVal = []
    retVals = {}
    line = out.split("\n")
    line.each do |n|
      if n =~ /10 GbE KR|MXL/
        if n =~ /(\S+)\s+/
          switchlist.push($1)
        end
      end
    end
    switchlist.each do |ioa|
        bladeModel = ""
        fullBladeModelList.each do|model|
          if model.to_s == serverModel.to_s
            bladeModel = "Full"
            break
          end
        end
        halfBladeModelList.each do|model|
          if model.to_s == serverModel.to_s
            bladeModel = "Half"
            break
          end
        end
        quaterBladeModelList.each do|model|
          if model.to_s == serverModel.to_s
          bladeModel = "Quater"
          break
          end
        end
        interfaceLocationList = []
        if  bladeModel == "Full"
          intLoc1 = "0/#{slot}"
          interfaceLoc1 = "Tengigabitethernet#{intLoc1}"
          #self.class.const_set(InterfaceLoc1,"Tengigabitethernet#{intLoc1})
          slotoperation = slot + 8
          intLoc2 = "0/#{slotoperation}"
          interfaceLoc2 = "Tengigabitethernet#{intLoc2}"
          interfaceLocationList = interfaceLocationList.push(interfaceLoc1)
          interfaceLocationList = interfaceLocationList.push(interfaceLoc2)
          
        end
        if  bladeModel == "Half"
          intLoc = "0/#{slot}"
          interfaceLoc = "Tengigabitethernet#{intLoc}"
          interfaceLocationList = interfaceLocationList.push(interfaceLoc)
        end
        if  bladeModel == "Quater"
          if slot =~ /(\d+)(\S+)/
            if $2 == "a"
              intLoc = "0/$1"
            end
            if $2 == "b"
              slotoperation = $1.to_i + 16
              intLoc = "0/#{slotoperation}"
            end
            if $2 == "c"
              slotoperation = $1.to_i + 8
              intLoc = "0/#{slotoperation}"
            end
            if $2 == "d"
              slotoperation = $1.to_i + 24
              intLoc = "0/#{slotoperation}"
            end
            interfaceLoc = "Tengigabitethernet#{intLoc}"
          end
          interfaceLocationList = interfaceLocationList.push(interfaceLoc)
      end
      retVal.push([ioa, interfaceLocationList])
    end
	retVals = { "#{serviceTag}" => retVal }
    return retVals
  end
end
