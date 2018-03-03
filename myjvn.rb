# coding: utf-8
require 'net/http'
require 'rexml/document'

def init(proxy_addr = nil, proxy_port = nil)
  @proxy_addr = proxy_addr
  @proxy_port = proxy_port
end

def search(keyword)
  http = Net::HTTP::Proxy(@proxy_addr, @proxy_port).new('jvndb.jvn.jp', 80)
  http.start do | session |
    time = Time.new
    start_year = time.year - 3
    puts "From " + start_year.to_s
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
      print item.elements['sec:identifier'].text,"\n\t",item.elements['title'].text, "\n\t", item.elements['dcterms:modified'].text,"\n"
      sec_cvss = item.elements['sec:cvss']
      print "\t",sec_cvss.attributes['vector'],"\t", sec_cvss.attributes['score'], "\n"
    end
    
  end
end

init()  # proxy なし
#search("postgresql")  # PostgreSQLをキーワードにして脆弱性情報取得
search("struts")
