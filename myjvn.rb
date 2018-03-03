# coding: utf-8
require 'net/http'
require 'rexml/document'

def init(proxy_addr = nil, proxy_port = nil)
  @proxy_addr = proxy_addr
  @proxy_port = proxy_port
end

def search(keyword)

  Net::HTTP::Proxy(@proxy_addr, @proxy_port).start('jvndb.jvn.jp', 80) do | session |
    time = Time.new
    start_year = time.year-3
    puts start_year
    response = session.get("/myjvn?method=getVulnOverviewList&rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n&keyword=#{keyword}&lang=ja&xsl=1&dateFirstPublishedStartY=#{start_year}")
    if response.code != '200'
      STDERR.puts "#{response.code} - #{response.message}"
      return
    end

#    puts response.body
    xml = REXML::Document.new(response.body)
#    num = xml.root.get_elements('/rdf:RDF/channel/items/rdf:Seq/rdf:li')

#   puts num
#    puts num.size
    xml.root.elements.each('/rdf:RDF/item') do |item|
#      p item
      print item.elements['sec:identifier'].text,"\t",item.elements['title'].text, " : ", item.elements['dcterms:modified'].text,"\n"
      sec_cvss = item.elements['sec:cvss']
      print sec_cvss.attributes['vector'],"\t", sec_cvss.attributes['score'], "\n"
    end
    
    exit 0
  end
end

init()  # proxy なし
#search("postgresql")  # PostgreSQLをキーワードにして脆弱性情報取得
search("struts")
