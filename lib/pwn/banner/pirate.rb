# frozen_string_literal: true

require 'colorize'

module PWN
  module Banner
    # This plugin processes images into readable text
    module Pirate
      # Supported Method Parameters::
      # PWN::Banner::Pirate.get

      public_class_method def self.get
        '
         @@@@@@@%%@@%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
         @@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@@@@
         @@@@@@@@@@%%%%@%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@
         @@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%@@@@@@@@@@@@@@@@@
         @@@@@@@@@@@@%@@@@%%%%%%%%%%%%#***#%%%%%%%%%%%@@@@@@@@@@@@@@@
         @@@@@@@@@@@@@%@@@%%%@%%%%%+-.......:+%%%%%%%%%%@@@@@@@@@@@@@
         @@@@@@@@@@@@@@@@@@@%%%%@#:............*%%%%%%%%%%%%@%@@@@@@@
         @@@@@@@@@@@@@@@@@@@@@%%%:.:.....*%%*:..%%%%%%%%%%%%%%%@@@@@@
         @@@@@@@@@@@@@@@@@@@@@%%%:.-%%:..%%%%*.:%%%%%%%%%%%%%%%%%%%@@
         @@@@@@@@@@@@@@@@%%@%%%%%%+=##::::*##-=#%%%%%%%%%%%%%%%%%%%%@
         @@@@@@@@@@@@@@@@@@@%*#%%@#==::*=.=+=*%%%%%%%%%%%%%%%%%%%%%%@
         @@@@@@@@@@@@@@@@@@@*-::=#@%%+::::*@%%=..%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@%*+--+#%%%%%%#+:...+%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@%%@#+-:+*+=-+*#%*:-%%%%%%%%%%%%%@%%%%%
         @@@@@@@@@@@@@@@@@@@@@+-+**+=-==:-+#%%%%%@%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@%*::=*#%@@%*=::-=#%%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@%%@@@@+:=%@@@@%%%@%+:..+%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@%#%@@@@@@%%@@%%%#*#%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@%%%%@@@@@%%%%%###%%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@%%%%%%%%@%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%@@%%%%%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%%%%%
         @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%%%%%%%%%%%%%%
         PWN
        '.light_black
      rescue StandardError => e
        raise e
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          #{self}.get

          #{self}.authors
        "
      end
    end
  end
end
