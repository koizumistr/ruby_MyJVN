# coding: utf-8
require 'net/http'
require 'rexml/document'

require_relative 'cvssinfo'

# 本ファイルには歴史的価値しかありません。

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
        if not sec_cvss.attributes['vector'].nil? and sec_cvss.attributes['vector'].length > 0
          result = CvssInfo.new(sec_cvss.attributes['vector'].match(/(([A-Zu:\/]{26}))/)[1], '2.0')
          mets = sec_cvss.attributes['vector'].match(/\(AV:(?<av>\w{1})\/AC:(?<ac>\w{1})\/Au:(?<au>\w{1})\/C:(?<c>\w{1})\/I:(?<i>\w{1})\/A:(?<a>\w{1})\)/)
          puts "\tAccess Vector: " + mets[:av] + " " + result.av_str
          puts "\tAccess Complexity: " + mets[:ac] + " " + result.ac_str
          puts "\tAuthentication: " + mets[:au] + " " + result.au_str
          puts "\tConfidentiality Impact: " + mets[:c] + " " + result.c_str
          puts "\tIntegrity Impact: " + mets[:i] + " " + result.i_str
          puts "\tAvailability Impact: " + mets[:a] + " " + result.a_str
          puts "calc score: " + result.score.to_s
          puts "calc severity: " + result.severity
        end
      end
      printval(item, 'dc:date')
      printval(item, 'dcterms:issued')
      printval(item, 'dcterms:modified')
    end
  end
end

puts "MyJVN API 3.1 is obsolete. You should use overview.rb. / MyJVN API 3.1は廃止されました。overview.rb を使ってください。"
exit!

init()  # proxy なし
search("postgresql")  # PostgreSQLをキーワードにして脆弱性情報取得
search("struts")
search("OpenSSL")
