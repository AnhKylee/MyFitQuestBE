﻿// <auto-generated> This file has been auto generated by EF Core Power Tools. </auto-generated>
#nullable disable
using System;
using System.Collections.Generic;

namespace MyFitQuest.API.Models;

public partial class Profile
{
    public int profile_id { get; set; }

    public int user_id { get; set; }

    public string name { get; set; }

    public string country { get; set; }

    public string city { get; set; }

    public string address { get; set; }

    public virtual User user { get; set; }
}