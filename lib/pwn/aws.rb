# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads SP aws
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AWS
    autoload :ACM, 'pwn/aws/acm'
    autoload :APIGateway, 'pwn/aws/api_gateway'
    autoload :ApplicationAutoScaling, 'pwn/aws/application_auto_scaling'
    autoload :ApplicationDiscoveryService, 'pwn/aws/application_discovery_service'
    autoload :AppStream, 'pwn/aws/app_stream'
    autoload :AutoScaling, 'pwn/aws/auto_scaling'
    autoload :Batch, 'pwn/aws/batch'
    autoload :Budgets, 'pwn/aws/budgets'
    autoload :CloudFormation, 'pwn/aws/cloud_formation'
    autoload :CloudFront, 'pwn/aws/cloud_front'
    autoload :CloudHSM, 'pwn/aws/cloud_hsm'
    autoload :CloudSearch, 'pwn/aws/cloud_search'
    autoload :CloudSearchDomain, 'pwn/aws/cloud_search_domain'
    autoload :CloudTrail, 'pwn/aws/cloud_trail'
    autoload :CloudWatch, 'pwn/aws/cloud_watch'
    autoload :CloudWatchEvents, 'pwn/aws/cloud_watch_events'
    autoload :CloudWatchLogs, 'pwn/aws/cloud_watch_logs'
    autoload :CodeBuild, 'pwn/aws/code_build'
    autoload :CodeCommit, 'pwn/aws/code_commit'
    autoload :CodeDeploy, 'pwn/aws/code_deploy'
    autoload :CodePipeline, 'pwn/aws/code_pipeline'
    autoload :CognitoIdentity, 'pwn/aws/cognito_identity'
    autoload :CognitoIdentityProvider, 'pwn/aws/cognito_identity_provider'
    autoload :CognitoSync, 'pwn/aws/cognito_sync'
    autoload :ConfigService, 'pwn/aws/config_service'
    autoload :DataPipeline, 'pwn/aws/data_pipleline'
    autoload :DatabaseMigrationService, 'pwn/aws/database_migration_service'
    autoload :DeviceFarm, 'pwn/aws/device_farm'
    autoload :DirectConnect, 'pwn/aws/direct_connect'
    autoload :DirectoryService, 'pwn/aws/directory_service'
    autoload :DynamoDB, 'pwn/aws/dynamo_db'
    autoload :DynamoDBStreams, 'pwn/aws/dynamo_db_streams'
    autoload :EC2, 'pwn/aws/ec2'
    autoload :ECR, 'pwn/aws/ecr'
    autoload :ECS, 'pwn/aws/ecs'
    autoload :EFS, 'pwn/aws/efs'
    autoload :EMR, 'pwn/aws/emr'
    autoload :ElastiCache, 'pwn/aws/elasti_cache'
    autoload :ElasticBeanstalk, 'pwn/aws/elastic_beanstalk'
    autoload :ElasticLoadBalancing, 'pwn/aws/elastic_load_balancing'
    autoload :ElasticLoadBalancingV2, 'pwn/aws/elastic_load_balancing_v2'
    autoload :ElasticTranscoder, 'pwn/aws/elastic_transcoder'
    autoload :ElasticsearchService, 'pwn/aws/elasticsearch_service'
    autoload :Firehose, 'pwn/aws/firehose'
    autoload :GameLift, 'pwn/aws/game_lift'
    autoload :Glacier, 'pwn/aws/glacier'
    autoload :Health, 'pwn/aws/health'
    autoload :IAM, 'pwn/aws/iam'
    autoload :ImportExport, 'pwn/aws/import_export'
    autoload :Inspector, 'pwn/aws/inspector'
    autoload :IoT, 'pwn/aws/iot'
    autoload :IoTDataPlane, 'pwn/aws/iot_data_plane'
    autoload :KMS, 'pwn/aws/kms'
    autoload :Kinesis, 'pwn/aws/kinesis'
    autoload :KinesisAnalytics, 'pwn/aws/kinesis_analytics'
    autoload :Lambda, 'pwn/aws/lambda'
    autoload :LambdaPreview, 'pwn/aws/lambda_preview'
    autoload :Lex, 'pwn/aws/lex'
    autoload :Lightsail, 'pwn/aws/lightsail'
    autoload :MachineLearning, 'pwn/aws/machine_learning'
    autoload :MarketplaceCommerceAnalytics, 'pwn/aws/marketplace_commerce_analytics'
    autoload :MarketplaceMetering, 'pwn/aws/marketplace_metering'
    autoload :OpsWorks, 'pwn/aws/ops_works'
    autoload :OpsWorksCM, 'pwn/aws/ops_works_cm'
    autoload :Pinpoint, 'pwn/aws/pinpoint'
    autoload :Polly, 'pwn/aws/polly'
    autoload :RDS, 'pwn/aws/rds'
    autoload :Redshift, 'pwn/aws/redshift'
    autoload :Rekognition, 'pwn/aws/rekognition'
    autoload :Route53, 'pwn/aws/route53'
    autoload :Route53Domains, 'pwn/aws/route53_domains'
    autoload :S3, 'pwn/aws/s3'
    autoload :SES, 'pwn/aws/ses'
    autoload :SMS, 'pwn/aws/sms'
    autoload :SNS, 'pwn/aws/sns'
    autoload :SQS, 'pwn/aws/sqs'
    autoload :SSM, 'pwn/aws/ssm'
    autoload :STS, 'pwn/aws/sts'
    autoload :SWF, 'pwn/aws/swf'
    autoload :ServiceCatalog, 'pwn/aws/service_catalog'
    autoload :Shield, 'pwn/aws/shield'
    autoload :SimpleDB, 'pwn/aws/simple_db'
    autoload :Snowball, 'pwn/aws/snowball'
    autoload :States, 'pwn/aws/states'
    autoload :StorageGateway, 'pwn/aws/storage_gateway'
    autoload :Support, 'pwn/aws/support'
    autoload :WAF, 'pwn/aws/waf'
    autoload :WAFRegional, 'pwn/aws/waf_regional'
    autoload :Workspaces, 'pwn/aws/workspaces'
    autoload :XRay, 'pwn/aws/x_ray'

    # Display a List of Every PWN::AWS Module

    public_class_method def self.help
      constants.sort
    end
  end
end
