# coding: utf-8
require 'net/https'
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

def score_calc_v2(av_c, ac_c, au_c, c_c, i_c, a_c)
  case av_c
  when 'L' then av = 0.395 # Local
  when 'A' then av = 0.464 # Adjacent Network
  when 'N' then av = 1.0 # Network
  end
  case ac_c
  when 'H' then ac = 0.35 # High
  when 'M' then ac = 0.61 # Medium
  when 'L' then ac = 0.71 # Low
  end
  case au_c
  when 'M' then au = 0.45 # Multiple
  when 'S' then au = 0.56 # Single
  when 'N' then au = 0.704 # None
  end
  case c_c
  when 'N' then c = 0.0 # None
  when 'P' then c = 0.275 # Partial
  when 'C' then c = 0.660 # Complete
  end
  case i_c
  when 'N' then i = 0.0 # None
  when 'P' then i = 0.275 # Partial
  when 'C' then i = 0.660 # Complete
  end
  case a_c
  when 'N' then a = 0.0 # None
  when 'P' then a = 0.275 # Partial
  when 'C' then a = 0.660 # Complete
  end
  exp = 20 * av * ac *au
  imp = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
  if imp > 0
    f_imp = 1.176
  else
    f_imp = 0
  end
  base_score = ((0.6 * imp) + (0.4 * exp) - 1.5) * f_imp
  return base_score.round(1)
end

def score_calc_v3(av_c, ac_c, pr_c, ui_c, s_c, c_c, i_c, a_c)
  case s_c
  when 'U' then s_changed = false
  when 'C' then s_changed = true
  end

  case av_c
  when 'N' then av = 0.85 # Network
  when 'A' then av = 0.62 # Adjacent Network
  when 'L' then av = 0.55 # Local
  when 'P' then av = 0.20 # Physical
  end
  case ac_c
  when 'H' then ac = 0.44 # High
  when 'L' then ac = 0.77 # Low
  end
  case pr_c
  when 'N' then pr = 0.85 # None
  when 'L' then # Low
    if s_changed
      pr = 0.68
    else
      pr = 0.62
    end
  when 'H' then # High
    if s_changed
      pr = 0.50
    else
      pr = 0.27
    end
  end
  case ui_c
  when 'N' then ui = 0.85 # None
  when 'R' then ui = 0.62 # Required
  end
#  case s_c
#  when 'U' then s = 0. # Unchanged
#  when 'C' then s = 0. # Changed
#  end
  case c_c
  when 'H' then c = 0.56 # High
  when 'L' then c = 0.22 # Low
  when 'N' then c = 0.0 # None
  end
  case i_c
  when 'H' then i = 0.56 # High
  when 'L' then i = 0.22 # Low
  when 'N' then i = 0.0 # None
  end
  case a_c
  when 'H' then a = 0.56 # High
  when 'L' then a = 0.22 # Low
  when 'N' then a = 0.0 # None
  end
  exp = 8.22 * av * ac * pr * ui
  imp = 1 - (1 - c) * (1 - i) * (1 - a)
  if s_changed
    imp_m = 7.52 * (imp - 0.029) - 3.25 * (imp - 0.02) ** 15
  else
    imp_m = 6.42 * imp
  end
  if s_changed
    base_score = [1.08 * (imp_m + exp), 10].min
  else
    base_score = [imp_m + exp, 10].min
  end
  return (base_score * 10).ceil / 10.0
end

def search(keyword)
  http = Net::HTTP::Proxy(@proxy_addr, @proxy_port).new('jvndb.jvn.jp', 443)
  http.use_ssl = true
  http.ca_file = './DigiCertHighAssuranceEVRootCA.pem'
  http.verify_mode = OpenSSL::SSL::VERIFY_PEER
  http.start do | session |
    time = Time.new
    start_year = time.year - 3
    puts "Vuls of '" + keyword + "' from " + start_year.to_s
    response = session.get("/myjvn?method=getVulnOverviewList&feed=hnd&rangeDatePublic=n&rangeDatePublished=n&rangeDateFirstPublished=n&keyword=#{keyword}&lang=ja&xsl=1&dateFirstPublishedStartY=#{start_year}")
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
          if sec_cvss.attributes['version'] == '3.0'
            mets = sec_cvss.attributes['vector'].match(/CVSS:3.0\/AV:(?<av>\w{1})\/AC:(?<ac>\w{1})\/PR:(?<pr>\w{1})\/UI:(?<ui>\w{1})\/S:(?<s>\w{1})\/C:(?<c>\w{1})\/I:(?<i>\w{1})\/A:(?<a>\w{1})/)
            puts "\tAttack Vector: " + mets[:av]
            puts "\tAttack Complexity: " + mets[:ac]
            puts "\tPrivileges Required: " + mets[:pr]
            puts "\tUser Interaction): " + mets[:ui]
            puts "\tScope: " + mets[:s]
            puts "\tConfidentiality Impact: " + mets[:c]
            puts "\tIntegrity Impact: " + mets[:i]
            puts "\tAvailability Impact: " + mets[:a]
            result =  score_calc_v3(mets[:av], mets[:ac], mets[:pr], mets[:ui], mets[:s], mets[:c], mets[:i], mets[:a])
            puts "calc score: " + result.to_s
            print "calc severity: "
            if result >= 9.0
              puts "Critical"
            elsif result >= 7.0
              puts "High"
            elsif result >= 4.0
              puts "Medium"
            elsif result >= 0.1
              puts "Low"
            else
              puts "None"
            end
          elsif sec_cvss.attributes['version'] == '2.0'
            mets = sec_cvss.attributes['vector'].match(/AV:(?<av>\w{1})\/AC:(?<ac>\w{1})\/Au:(?<au>\w{1})\/C:(?<c>\w{1})\/I:(?<i>\w{1})\/A:(?<a>\w{1})/)
            puts "\tAccess Vector: " + mets[:av]
            puts "\tAccess Complexity: " + mets[:ac]
            puts "\tAuthentication: " + mets[:au]
            puts "\tConfidentiality Impact: " + mets[:c]
            puts "\tIntegrity Impact: " + mets[:i]
            puts "\tAvailability Impact: " + mets[:a]
            result =  score_calc_v2(mets[:av], mets[:ac], mets[:au], mets[:c], mets[:i], mets[:a])
            puts "calc score: " + result.to_s
            print "calc severity: "
            if result >= 7.0
              puts "High"
            elsif result >= 4.0
              puts "Medium"
            else
              puts "Low"
            end
          end
          puts "cvss:type: " + sec_cvss.attributes['type']
        end
      end
      printval(item, 'dc:date')
      printval(item, 'dcterms:issued')
      printval(item, 'dcterms:modified')
    end
  end
end

init()  # proxy なし
search("postgresql")  # PostgreSQLをキーワードにして脆弱性情報取得
search("struts")
search("OpenSSL")
