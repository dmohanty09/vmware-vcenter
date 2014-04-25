module ASM
  class Error < StandardError
  end
  class CommandException     < Error; end
  class SyncException        < Error; end
  class PuppetEventException < Error; end
end
