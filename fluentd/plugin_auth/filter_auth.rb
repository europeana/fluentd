# This plugin uses https://github.com/jwt/ruby-jwt (MIT license) to parse data in an Authorization header. If the header
# contains a JWT (Bearer token header) then we extract claim data and insert this in the record.
# If the Authorization header contains APIKEY <key> values then this 'key' value is inserted in the record.
# If the provided header is empty or doesn't contain a valid JWT, then no data is inserted. Warnings are logged for
# tokens that can't be parsed. By default Basic tokens are silently ignored, but warnings can be enabled for it.
# 
# @author Patrick Ehlert
#
# Example usage:
#
#     <filter *>
#         @type jwt
#         token_key authorization_header
#         remove_token_key true
#         skip_basic_token true
#         <record>
#             algorithm        header.alg
#             subject          payload.sub
#             expiration_time  payload.exp
#         </record>
#     </filter>
#

require 'fluent/plugin/filter'
require 'jwt'

module Fluent::Plugin
    class JwtFilter < Filter
        Fluent::Plugin.register_filter('auth', self)

        # We use lowercase because we first convert values to lowercase to do a case-insensitive check
        BEARER_TOKEN_PREFIX = "bearer"
        BASIC_TOKEN_PREFIX  = "basic"
        APIKEY_PREFIX       = "apikey"

        JWT_COMPONENTS = ["payload", "header"]

        config_set_default :@log_level, "warn"

        # See also https://docs.fluentd.org/plugin-helper-overview/api-plugin-helper-record_accessor
        # and https://docs.fluentd.org/plugin-helper-overview/api-plugin-helper-inject
        helpers :record_accessor, :inject

        # Plugin parameters
        desc 'Specify the field name that contains the credentials to parse (JWT or APIKEY). Generally this is the \'Authorization\' field.'
        config_param :credentials_key, :string, default: nil
        desc 'Remove the "credentials_key" field from the record when parsing was successful (default = false)'
        config_param :remove_credentials_key, :bool, default: false
        desc 'Silently skip "Basic" base64 encoded tokens (default = true). If false it will generate an error for each basic token'
        config_param :skip_basic_token, :bool, default: true

        def configure(conf)
            super

            if @credentials_key.nil?
                raise Fluent::ConfigError, "Please set the credentials_key parameter."
            end
            log.info("[auth] - credentials key = " + @credentials_key)
            @token_accessor = record_accessor_create('$.' + @credentials_key)

            @fields_map = {}
            conf.elements.select { |element| element.name == 'record' }.each {
                |element| element.each_pair { |k, v|
                    element.has_key?(k) # to suppress unread configuration warning

                    # validate that each value starts with a valid JWT component and then a period
                    if (v.start_with?(*JWT_COMPONENTS.map { |c| c + "." })) then
                        @fields_map[k] = v
                        log.trace("[auth - jwt] - field "+ k + ", value "+ v)
                    else
                        raise Fluent::ConfigError, "Unsupported JWT component: " + v 
                    end
                }
            }
        end

        def filter(tag, time, record)
            filtered_record = add_fields(record)
            if filtered_record
                record = filtered_record
            end
            record = inject_values_to_record(tag, time, record)
            record
        end

        def add_fields(record)
            # get token
            token = @token_accessor.call(record).to_s
            log.trace("[auth] - token = " + token)
            return record if !token || token.empty?

            # split into token type and data
            token_split = token.split(" ", 2)
            if (token_split.size() != 2)
                log.warn("[auth] - Invalid token: " + token)
                return record
            end
            token_type = token_split[0].downcase    # convert to downcase for easy comparison
            token_data = token_split[1]
            log.trace("[auth] - token type = " + token_type)

            if (token_type == BEARER_TOKEN_PREFIX)
                parse_jwt(record, token_data)
            elsif (token_type == APIKEY_PREFIX)
                record["client_key"] = token_data.strip
            elsif (token_type == BASIC_TOKEN_PREFIX)
                if (!skip_basic_token)
                    log.warn("[auth] - Basic tokens are not supported: " + token)
                end
            else
                log.warn("[auth] - Unknown token type: " + token)
            end
            return record
        end

        def parse_jwt(record, token)
            begin
                decoded_token = JWT_COMPONENTS.zip(JWT.decode(token, nil, false)).to_h
                log.trace("[auth - jwt] - decoded token = " + decoded_token.to_s)

                # insert requested data
                @fields_map.each do |key_to_add, path|
                    p = path.split(".")
                    value_to_add = decoded_token[p[0]][p[1]].to_s
                    log.trace("[auth - jwt] - adding " + key_to_add + " with value " + value_to_add)
                    record[key_to_add] = value_to_add
                end

                @token_accessor.delete(record) if @remove_token_key
            rescue JWT::DecodeError => e
                log.error("[auth - jwt] - error decoding token: " + token.to_s)
            end
        end

    end
end