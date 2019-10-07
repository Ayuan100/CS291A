# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  status = 200
  if event['path'] == '/token'
    if event['httpMethod'] == 'POST' 
      headers = event['headers'].transform_keys(&:downcase)
      if headers['content-type'] == 'application/json'
        data = event['body']
        status = 422
        if data && data.is_a?(String)
          begin
            jsonData = JSON.parse(data)
            if jsonData 
              # generate token
              payload = {
                data: jsonData,
                exp: Time.now.to_i + 5,
                nbf: Time.now.to_i + 2
              }
              token = JWT.encode payload, 'NOTASECRET', 'HS256'
              return {
                body: {"token": token}.to_json + "\n",
                statusCode: 201
              }
            end
          rescue
          end
        end
      else
        status = 415
      end
    else
      status = 405
    end
  elsif event['path'] == '/'
    if event['httpMethod'] == 'GET'
      headers = event['headers'].transform_keys(&:downcase)
      auth = headers && headers['authorization']
      status = 403
      if auth && (auth.start_with? 'Bearer ')
        token = auth[7..-1]
        if token
          begin
            parsedToken = JWT.decode token, 'NOTASECRET', false, { algorithm: 'HS256' }
            exp = parsedToken && parsedToken[0]['exp']
            nbf = parsedToken && parsedToken[0]['nbf']
            data = parsedToken && parsedToken[0]['data']
            if exp && nbf
              if exp > Time.now.to_i &&  nbf <= Time.now.to_i
                return {
                  body: data.to_json + "\n",
                  statusCode: 200
                }
              else 
                status = 401
              end
            end
          rescue JWT::DecodeError => err
            # process decode error
            return {
              body: err.to_json + "\n",
              statusCode: 403
            }
          end
        end
      end
    else
      status = 405
    end
  else
    status = 404
  end

  response(body: event, status: status)
end

def response(body: nil, status: 200)
  {
    body: body ? body.to_json + "\n" : '',
    statusCode: status
  }
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  ENV['JWT_SECRET'] = 'NOTASECRET'

  # Call /token
  PP.pp main(context: {}, event: {
               'body' => '{"name": "bboe"}',
               'headers' => { 'Content-Type' => 'application/json' },
               'httpMethod' => 'POST',
               'path' => '/token'
             })

  # Generate a token
  payload = {
    data: { user_id: 128 },
    exp: Time.now.to_i + 1,
    nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
               'headers' => { 'Authorization' => "Bearer #{token}",
                              'Content-Type' => 'application/json' },
               'httpMethod' => 'GET',
               'path' => '/'
             })
end
