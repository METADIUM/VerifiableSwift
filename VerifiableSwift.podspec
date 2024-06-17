#
# Be sure to run `pod lib lint VerifiableSwift.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'VerifiableSwift'
  s.version          = '0.2.3'
  s.summary          = 'Verifiable Credential and Presentation of Metadium.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
Verifiable Credential and Presentation of Metadium.
                       DESC

  s.homepage         = 'https://github.com/METADIUM/VerifiableSwift'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'YoungBae Jeon' => 'ybjeon@cplabs.io' }
  s.source           = { :git => 'https://github.com/METADIUM/VerifiableSwift.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = '15.0'

  s.source_files = 'Sources/VerifiableSwift/Classes/**/*'
  
  # s.resource_bundles = {
  #   'VerifiableSwift' => ['VerifiableSwift/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
  s.dependency 'JWTsSwift'
end
