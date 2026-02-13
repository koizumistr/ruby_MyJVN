# coding: utf-8

require 'net/https'
require 'rexml/document'

require_relative 'cvssinfo'

def init(proxy_addr = nil, proxy_port = nil)
  @proxy_addr = proxy_addr
  @proxy_port = proxy_port
end

def printval(item, elem_name)
  item.elements.each(elem_name) do |elem|
    print "#{elem_name}: #{elem.text}\n"
  end
end

def getinfo(id)
  http = Net::HTTP::Proxy(@proxy_addr, @proxy_port).new('jvndb.jvn.jp', 443)
  http.use_ssl = true
  http.ca_file = './DigiCertGlobalRootG2.crt.pem'
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.start do |session|
    puts "=== Info of #{id} ==="
    response = session.get("/myjvn?method=getVulnDetailInfo&feed=hnd&vulnId=#{id}&lang=ja")
    if response.code != '200'
      warn "#{response.code} - #{response.message}"
      break
    end

#    puts response.body
    xml = REXML::Document.new(response.body)

    if xml.root.elements['/VULDEF-Document/status:Status'].nil?
      warn 'Fatal error'
      break
    end

    if xml.root.elements['/VULDEF-Document/status:Status'].attributes['totalResRet'] == '0'
      warn 'No results'
      break
    end

    vulinfo = xml.root.elements['/VULDEF-Document/Vulinfo']
    puts "VulinfoID: #{vulinfo.elements['VulinfoID'].text}"
    data = vulinfo.elements['VulinfoData']
    puts "Title: #{data.elements['Title'].text}"
    puts "Overview: #{data.elements['VulinfoDescription/Overview'].text}"
    data.elements.each('Impact/Cvss') do |cvss|
      version = cvss.attributes['version']
      severity = cvss.elements['Severity'].text
      score = cvss.elements['Base'].text # score
      vector = cvss.elements['Vector'].text
      puts "version: #{version}"
      puts "\tscore: #{score}"
      puts "\tseverity: #{severity}"
      next if vector.nil? || vector.empty?

      result = CvssInfo.new(vector, version)
      puts "\tcalc score: #{result.score}"
      puts "\tcalc severity: #{result.severity}"
    end
    data.elements.each('Impact/ImpactItem') do |item|
      puts "ImpactItemDesc: #{item.elements['Description'].text}"
    end
    data.elements.each('Solution/SolutionItem') do |item|
      puts "SolutionItemDesc: #{item.elements['Description'].text}"
    end
    data.elements.each('Related/RelatedItem') do |item|
      puts '-- RelatedItem --'
      printval(item, 'Name')
      printval(item, 'VulinfoID')
      printval(item, 'Title')
      printval(item, 'URL')
    end
    puts "DateFirstPublished: #{data.elements['DateFirstPublished'].text}"
    puts "DateLastUpdated: #{data.elements['DateLastUpdated'].text}"
    puts "DatePublic: #{data.elements['DatePublic'].text}"
  end
end

init # proxy なし
getinfo('JVNDB-2017-001234')
getinfo('JVNDB-2016-001234')
getinfo('JVNDB-2017-000432')
getinfo('JVNDB-2037-000432')
