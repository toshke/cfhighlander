require_relative './iam_helper'

def render_lambda_functions(cfndsl, lambdas, lambda_metadata, distribution, max_azs=5)

  custom_policies = (lambdas.key? 'custom_policies') ? lambdas['custom_policies'] : {}
  render_default_lambda = false
  if lambdas.key? 'vpc' and lambdas['vpc']
    lambdas['functions'].each do |key,config| lambdas['functions'][key]['vpc'] = lambdas['vpc'] end
  end

  lambdas['roles'].each do |lambda_role, role_config|
    cfndsl.IAM_Role("LambdaRole#{lambda_role}") do
      AssumeRolePolicyDocument service_role_assume_policy('lambda')
      Path '/'
      unless role_config['policies_inline'].nil?
        Policies(
            IAMPolicies.new(custom_policies).create_policies(role_config['policies_inline'])
        )
      end

      unless role_config['policies_managed'].nil?
        ManagedPolicyArns(role_config['policies_managed'])
      end
    end
  end

  lambdas['functions'].each do |key, lambda_config|
    name = key
    environment = lambda_config['environment'] || {}

    # Create Lambda function
    function_name = name
    Lambda_Function(function_name) do
      Code({
          S3Bucket: distribution['bucket'],
          S3Key: "#{distribution['prefix']}/#{distribution['version']}/#{lambda_metadata['path'][key]}"
      })

      Environment(Variables: Hash[environment.collect { |k, v| [k, v] }])

      Handler(lambda_config['handler'] || 'index.handler')
      MemorySize(lambda_config['memory'] || 128)
      Role(FnGetAtt("LambdaRole#{lambda_config['role']}", 'Arn'))
      Runtime(lambda_config['runtime'])
      Timeout(lambda_config['timeout'] || 10)
      if !lambda_config['vpc'].nil? && lambda_config['vpc']

        if lambda_config['vpc'] == 'auto'
          unless (defined? az_conditional_resources) == 'method'
            raise StandardError, 'az_conditional_resources required for lambdas and auto vpc config (Add DependsOn to vpc component)'
          end
          config = {
              SubnetIds: az_conditional_resources('SubnetCompute', max_azs),
              SecurityGroupIds: Ref('LambdaDefaultSecurityGroup')
          }
          render_default_lambda = true
        else
          config = {
              SubnetIds: lambda_config['vpc']['subnets'],
              SecurityGroupIds: lambda_config['vpc']['secgroups']
          }
        end
        VpcConfig(config)
      end

      if !lambda_config['named'].nil? && lambda_config['named']
        FunctionName(name)
      end
    end

    Lambda_Version("#{name}Version#{lambda_metadata['version'][key]}") do
      DeletionPolicy('Retain')
      FunctionName(Ref(name))
      CodeSha256(lambda_metadata['sha256'][key])
    end

    # Generate lambda function Policy
    unless lambda_config['allowed_sources'].nil?
      i = 1
      lambda_config['allowed_sources'].each do |source|
        Lambda_Permission("#{name}Permissions#{i}") do
          FunctionName(Ref(name))
          Action('lambda:InvokeFunction')
          Principal(source['principal'])
          if source.key? 'source_arn'
            SourceArn source['source_arn']
          end
        end
        i += 1
      end
    end

    # Scheduled triggering of lambda function
    if lambda_config.key?('schedules')
      lambda_config['schedules'].each_with_index do |schedule, index|
        Events_Rule("Lambda#{name}Schedule#{index}") do
          ScheduleExpression("cron(#{schedule['cronExpression']})")
          State('ENABLED')
          target = {
              'Arn' => FnGetAtt(name, 'Arn'), 'Id' => "lambda#{name}",
          }
          target['Input'] = schedule['payload'] if schedule.key?('payload')
          Targets([target])
        end
      end
    end

    if render_default_lambda
      EC2_SecurityGroup(:LambdaDefaultSecurityGroup) do
        VpcId Ref('VPCId')
        GroupDescription 'Cfhighlander Lambda Security Group'
        SecurityGroupIngress [ {CidrIp: '0.0.0.0/0',IpProtocol: 'tcp', FromPort: 1024, ToPort: 65535} ]
        SecurityGroupEgress  [ {CidrIp: '0.0.0.0/0',IpProtocol: 'tcp', FromPort: 0, ToPort: 65535} ]
        SecurityGroupEgress  [ {CidrIp: '0.0.0.0/0',IpProtocol: 'udp', FromPort: 0, ToPort: 65535} ]
      end
    end

  end
end