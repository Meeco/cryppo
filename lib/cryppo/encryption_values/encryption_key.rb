module Cryppo
  module EncryptionValues
    class EncryptionKey < BasicObject

      def initialize(encryption_key)
        @encryption_key = encryption_key
      end

      def unwrap_key
        @encryption_key
      end

      def raise_serialization_error
        ::Kernel.raise CoercionOfEncryptedKeyToString, 'This is a key used for encryption and should not be implicitly coerced to a String.  It needs to be guarded and protected.  Explicitly use the `unwrap_key` method to use the enclosed encryption key.'
      end

      alias :to_s :raise_serialization_error
      alias :to_str :raise_serialization_error
      alias :marshal_dump :raise_serialization_error

      module Helpers
        module_function

        def wrap_encryption_key(key)
          case key
          when EncryptionKey
            key
          else
            EncryptionKey.new(key)
          end
        end

        def unwrap_encryption_key(key)
          case key
          when EncryptionKey
            key.unwrap_key
          else
            key
          end
        end

      end

    end
  end
end
