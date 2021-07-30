variable "function-name" {
    default = "exception-notifier"
}

variable "monitored-log-group-names" { 
    type = set(string)
    default = []
}

variable "cloudwatch-filter-pattern" {
    type = string
    default = "?ERROR ?WARN ?5xx"
}

variable "notification-recipient-email" {
    type = string
}