terraform{
    required_version =">=1.4.0"
}

resource "terraform_data" "demo"{
    input = "tf-risk first plan"
}