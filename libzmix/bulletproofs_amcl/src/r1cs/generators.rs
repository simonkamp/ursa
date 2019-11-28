use amcl_wrapper::group_elem::{GroupElement, GroupElementVector};
use amcl_wrapper::group_elem_g1::{G1Vector, G1};

// The PartialEq is needed to avoid creating new `Prover`/`Verifier` objects when passed
// generators are same.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[allow(non_snake_case)]
pub struct Generators {
    pub G: G1Vector,
    pub H: G1Vector,
    pub g: G1,
    pub h: G1,
}

impl Generators {
    pub fn new(label: &[u8], size: usize) -> Self {
        // prefix for `G` is `label`||" : "||"G"
        let G = Self::get_generators(&[label, " : G".as_bytes()].concat(), size);
        // prefix for `H` is `label`||" : "||"H"
        let H = Self::get_generators(&[label, " : H".as_bytes()].concat(), size);
        let g = G1::from_msg_hash(&[label, " : g".as_bytes()].concat());
        let h = G1::from_msg_hash(&[label, " : h".as_bytes()].concat());
        Self { G, H, g, h }
    }

    pub fn size(&self) -> usize {
        self.G.len()
    }

    /// Check if the number of generators in `G` is same as in `H`
    pub fn is_valid(&self) -> bool {
        // TODO: Should probably add checks like if generators `g`, `h` and all in `G` and `H`
        // were constructed by hashing a given label and indices where necessary
        self.G.len() == self.H.len()
    }

    fn get_generators(prefix: &[u8], n: usize) -> G1Vector {
        let mut gens = G1Vector::with_capacity(n);
        let delimiter = " : ".as_bytes();
        for i in 1..n + 1 {
            // Hashing `prefix`||" : "||`i`
            gens.push(G1::from_msg_hash(
                &[prefix, &delimiter, &i.to_string().as_bytes()].concat(),
            ));
        }
        gens
    }
}
