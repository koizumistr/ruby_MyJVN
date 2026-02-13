class CvssInfo
  attr_reader :version
  attr_reader :av_str, :ac_str, :pr_str, :ui_str, :s_str, :c_str, :i_str, :a_str
  attr_reader :au_str # for v2
  attr_reader :score, :severity

  def initialize(vector, ver = '3.0')
    @version = ver

    if @version == '3.0'
      if vector.size == 0
        @severity = 'Unknown'
        return
      elsif vector.size != 44
        raise 'illegal vector'
      end

      @version = ver

      mets = vector.match(/CVSS:3.0\/AV:(?<av>\w{1})\/AC:(?<ac>\w{1})\/PR:(?<pr>\w{1})\/UI:(?<ui>\w{1})\/S:(?<s>\w{1})\/C:(?<c>\w{1})\/I:(?<i>\w{1})\/A:(?<a>\w{1})/)
      case mets[:s]
      when 'U'
        s_changed = false
        @s_str = 'Unchanged'
      when 'C'
        s_changed = true
        @s_str = 'Changed'
      end

      case mets[:av]
      when 'N'
        av = 0.85
        @av_str = 'Network'
      when 'A'
        av = 0.62
        @av_str = 'Adjacent Network'
      when 'L'
        av = 0.55
        @av_str = 'Local'
      when 'P'
        av = 0.20
        @av_str = 'Physical'
      end

      case mets[:ac]
      when 'H'
        ac = 0.44
        @ac_str = 'High'
      when 'L'
        ac = 0.77
        @ac_str = 'Low'
      end

      case mets[:pr]
      when 'N'
        pr = 0.85
        @pr_str = 'None'
      when 'L'
        @pr_str = 'Low'
        if s_changed
          pr = 0.68
        else
          pr = 0.62
        end
      when 'H'
        @pr_str = 'High'
        if s_changed
          pr = 0.50
        else
          pr = 0.27
        end
      end

      case mets[:ui]
      when 'N'
        ui = 0.85
        @ui_str = 'None'
      when 'R'
        ui = 0.62
        @ui_str = 'Required'
      end

#      case mets[:s]
#      when 'U' then
#      when 'C' then
#      end

      case mets[:c]
      when 'H'
        c = 0.56
        @c_str = 'High'
      when 'L'
        c = 0.22
        @c_str = 'Low'
      when 'N'
        c = 0.0
        @c_str = 'None'
      end

      case mets[:i]
      when 'H'
        i = 0.56
        @i_str = 'High'
      when 'L'
        i = 0.22
        @i_str = 'Low'
      when 'N'
        i = 0.0
        @i_str = 'None'
      end

      case mets[:a]
      when 'H'
        a = 0.56
        @a_str = 'High'
      when 'L'
        a = 0.22
        @a_str = 'Low'
      when 'N'
        a = 0.0
        @a_str = 'None'
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
      @score = (base_score * 10).ceil / 10.0

      if @score >= 9.0
        @severity = 'Critical'
      elsif @score >= 7.0
        @severity = 'High'
      elsif @score >= 4.0
        @severity = 'Medium'
      elsif @score >= 0.1
        @severity = 'Low'
      else
        @severity = 'None'
      end
    elsif @version == '2.0'
      if vector.size == 0
        @severity = 'Unknown'
        return
      elsif vector.size != 26
        raise 'illegal vector'
      end

      mets = vector.match(/AV:(?<av>\w{1})\/AC:(?<ac>\w{1})\/Au:(?<au>\w{1})\/C:(?<c>\w{1})\/I:(?<i>\w{1})\/A:(?<a>\w{1})/)
      case mets[:av]
      when 'L'
        av = 0.395
        @av_str = 'Local'
      when 'A'
        av = 0.464
        @av_str = 'Adjacent Network'
      when 'N'
        av = 1.0
        @av_str = 'Network'
      end
      case mets[:ac]
      when 'H'
        ac = 0.35
        @ac_str = 'High'
      when 'M'
        ac = 0.61
        @ac_str = 'Medium'
      when 'L'
        ac = 0.71
        @ac_str = 'Low'
      end
      case mets[:au]
      when 'M'
        au = 0.45
        @au_str = 'Multiple'
      when 'S'
        au = 0.56
        @au_str = 'Single'
      when 'N'
        au = 0.704
        @au_str = 'None'
      end
      case mets[:c]
      when 'N'
        c = 0.0
        @c_str = 'None'
      when 'P'
        c = 0.275
        @c_str = 'Partial'
      when 'C'
        c = 0.660
        @c_str = 'Complete'
      end
      case mets[:i]
      when 'N'
        i = 0.0
        @i_str = 'None'
      when 'P'
        i = 0.275
        @i_str = 'Partial'
      when 'C'
        i = 0.660
        @i_str = 'Complete'
      end
      case mets[:a]
      when 'N'
        a = 0.0
        @a_str = 'None'
      when 'P'
        a = 0.275
        @a_str = 'Partial'
      when 'C'
        a = 0.660
        @a_str = 'Complete'
      end

      exp = 20 * av * ac * au
      imp = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
      if imp > 0
        f_imp = 1.176
      else
        f_imp = 0
      end
      base_score = ((0.6 * imp) + (0.4 * exp) - 1.5) * f_imp
      @score = base_score.round(1)

      if @score >= 7.0
        @severity = 'High'
      elsif @score >= 4.0
        @severity = 'Medium'
      else
        @severity = 'Low'
      end
    else
      raise 'unknown version'
    end
  end
end
