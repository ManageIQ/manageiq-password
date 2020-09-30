RSpec.describe ManageIQ::Password::PasswordMixin do
  let(:fake_ar_base) do
    Class.new do
      attr_reader :attributes

      def initialize
        @attributes = {}
      end

      def read_attribute(attribute)
        @attributes[attribute]
      end

      def write_attribute(attribute, value)
        @attributes[attribute] = value
      end

      def self.define_column(column)
        include Module.new do
          define_method(column) do
            read_attribute(column)
          end

          define_method("#{column}=") do |value|
            write_attribute(column, value)
          end
        end
      end

      def self.class_attribute(attribute)
        instance_eval(<<~DEF, __FILE__, __LINE__ + 1)
          def self.#{attribute}
            @#{attribute}
          end

          def self.#{attribute}=(value)
            @#{attribute} = value
          end
        DEF
      end
    end
  end

  let(:fake_ar_model) do
    Class.new(fake_ar_base) do
      define_column :username
      define_column :password

      include ManageIQ::Password::PasswordMixin
      encrypt_column :password
    end
  end

  it ".encrypted_columns" do
    expect(fake_ar_model.encrypted_columns).to match_array(%w[password])
  end

  it "underlying columns are stored encrypted" do
    m = fake_ar_model.new

    m.password = "pa$$w0rd"
    expect(m.attributes[:password]).to be_encrypted
  end

  it "creates getters and setters" do
    m = fake_ar_model.new

    m.password = "pa$$w0rd"
    expect(m.password).to eq("pa$$w0rd")
    expect(m.password_encrypted).to be_encrypted

    m.password_encrypted = ManageIQ::Password.encrypt("s00persecret")
    expect(m.password).to eq("s00persecret")
    expect(m.password_encrypted).to be_encrypted
  end
end
