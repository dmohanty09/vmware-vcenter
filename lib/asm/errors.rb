module ASM
  class Error < StandardError
  end
  class CommandException     < Error; end
  class SyncException        < Error; end
  class PuppetEventException < Error; end

  # A UserException message can be displayed directly to the user
  class UserException < Error; end

end
