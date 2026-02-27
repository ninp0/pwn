# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SAST modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    # Collection of Agentic AI Modules. These modules are designed to perform specific tasks autonomously, such as interacting with APIs, performing reconnaissance, or automating exploitation steps. Each module is designed to be used within an agentic AI framework, allowing for the creation of intelligent agents that can perform complex tasks without human intervention. The Agent module serves as a namespace for all agentic AI modules, providing a structured way to organize and access these functionalities. By using autoload, we ensure that each module is only loaded into memory when it's actually needed, optimizing resource usage and improving performance.
    module Agent
      # Agentic AI Modules
      autoload :BurpSuite, 'pwn/ai/agent/burp_suite'

      # Display a List of Every PWN::AI Module

      public_class_method def self.help
        constants.sort
      end
    end
  end
end
