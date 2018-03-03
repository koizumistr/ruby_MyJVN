# coding: utf-8
require 'net/http'
require 'rexml/document'

def init(proxy_addr = nil, proxy_port = nil)
  @proxy_addr = proxy_addr
  @proxy_port = proxy_port
end

def printval(item, elem_name)
  item.elements.each(elem_name) do |elem|
    print elem_name + ": " + elem.text + "\n"
  end
end

def search(keyword)
  http = Net::HTTP::Proxy(@proxy_addr, @proxy_port).new('jvndb.jvn.jp', 80)
  http.start do | session |
    time = Time.new
    start_year = time.year - 3
    puts "Vuls of '" + keyword + "' from " + start_year.to_s
    response = session.get("/myjvn?method=getVulnOverviewList&rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n&keyword=#{keyword}&lang=ja&xsl=1&dateFirstPublishedStartY=#{start_year}")
    if response.code != '200'
      STDERR.puts "#{response.code} - #{response.message}"
      return
    end

    xml = REXML::Document.new(response.body)

    if xml.root.elements['/rdf:RDF/status:Status'].nil?
      STDERR.puts "Fatal error"
      return
    end

    if xml.root.elements['/rdf:RDF/status:Status'].attributes['totalResRet'] == '0'
      STDERR.puts "No results"
      return
    end

    xml.root.elements.each('/rdf:RDF/item') do |item|
      puts "==================================================="
      print "title: " + item.elements['title'].text + "\n"
      print "link: " + item.elements['link'].text + "\n"
      printval(item, 'description')
      printval(item, 'dc:language')
      printval(item, 'dc:publisher')
      printval(item, 'dc:rights')
      printval(item, 'dc:creator')
      printval(item, 'dc:subject')
      printval(item, 'dc:identifier')
      printval(item, 'dc:relation')
      printval(item, 'sec:identifier')
      printval(item, 'sec:references')
#      printval(item, 'sec:cpe-item')
      item.elements.each('sec:cvss') do |sec_cvss|
        puts "cvss:version: " + sec_cvss.attributes['version']
        puts "cvss:severity: " + sec_cvss.attributes['severity']
        puts "cvss:score: " + sec_cvss.attributes['score']
        puts "cvss:vector: " + sec_cvss.attributes['vector']
      end
      printval(item, 'dc:date')
      printval(item, 'dcterms:issued')
      printval(item, 'dcterms:modified')
    end
    
  end
end

init()  # proxy なし
search("postgresql")  # PostgreSQLをキーワードにして脆弱性情報取得
#search("struts")
#search("OpenSSL")
