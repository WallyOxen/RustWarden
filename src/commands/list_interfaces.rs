use pnet::datalink::interfaces;

pub fn list_interfaces() {
    for interface in interfaces() {
        println!("{}", interface);
    }
}
